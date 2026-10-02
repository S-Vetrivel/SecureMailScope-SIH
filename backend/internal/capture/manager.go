package capture

import (
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type Interface struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Up   bool   `json:"up"`
}

type CaptureStats struct {
	Status          string `json:"status"`
	Interface       string `json:"interface"`
	Duration        string `json:"duration"`
	PacketsCaptured int    `json:"packets_captured"`
	BytesCaptured   int    `json:"bytes_captured"`
	PacketsPerSec   int    `json:"packets_per_sec"`
	CurrentChunk    string `json:"current_chunk"`
	QueueDepth      int    `json:"queue_depth"`
	AnalyzerWorkers int    `json:"analyzer_workers"`
}

type LiveCaptureManager struct {
	mu sync.Mutex

	activeInterface string
	status          string // ACTIVE, STOPPED, ERROR

	startTime    time.Time
	packets      int
	bytes        int
	currentChunk string

	stopChan chan struct{}

	chunkSeconds int
	workers      int
	outputDir    string
	bpfFilter    string

	analyzeFunc   func(pcapPath string)
	eventEmitter  func(eventType string, data interface{})
}

func NewLiveCaptureManager(outputDir string, analyzeFunc func(string), eventEmitter func(string, interface{})) *LiveCaptureManager {
	_ = os.MkdirAll(outputDir, 0755)
	
	chunkSecs := 10
	if val := os.Getenv("CAPTURE_CHUNK_SECONDS"); val != "" {
		fmt.Sscanf(val, "%d", &chunkSecs)
	}
	workers := 2
	if val := os.Getenv("ANALYSIS_WORKERS"); val != "" {
		fmt.Sscanf(val, "%d", &workers)
	}

	return &LiveCaptureManager{
		status:       "STOPPED",
		chunkSeconds: chunkSecs,
		workers:      workers,
		outputDir:    outputDir,
		analyzeFunc:  analyzeFunc,
		eventEmitter: eventEmitter,
		bpfFilter:    "tcp and (port 25 or port 465 or port 587 or port 143 or port 993 or port 110 or port 995)",
	}
}

func (m *LiveCaptureManager) GetInterfaces() ([]Interface, error) {
	var res []Interface
	netIfaces, _ := net.Interfaces()
	for _, iface := range netIfaces {
		res = append(res, Interface{
			Name: iface.Name,
			Type: "ethernet",
			Up:   (iface.Flags & net.FlagUp) != 0,
		})
	}
	return res, nil
}

func (m *LiveCaptureManager) Start(iface string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.status == "ACTIVE" {
		return fmt.Errorf("capture is already active on %s", m.activeInterface)
	}

	m.activeInterface = iface
	m.status = "ACTIVE"
	m.stopChan = make(chan struct{})
	m.startTime = time.Now()
	m.packets = 0
	m.bytes = 0

	if m.eventEmitter != nil {
		m.eventEmitter("capture.started", map[string]string{"interface": iface})
	}

	go m.captureLoop(iface)

	return nil
}

func (m *LiveCaptureManager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.status != "ACTIVE" {
		return fmt.Errorf("capture is not active")
	}

	close(m.stopChan)
	m.status = "STOPPED"
	
	if m.eventEmitter != nil {
		m.eventEmitter("capture.stopped", map[string]string{"interface": m.activeInterface})
	}
	return nil
}

func (m *LiveCaptureManager) Stats() CaptureStats {
	m.mu.Lock()
	defer m.mu.Unlock()

	dur := time.Since(m.startTime).Seconds()
	pps := 0
	if dur > 0 && m.status == "ACTIVE" {
		pps = int(float64(m.packets) / dur)
	}

	return CaptureStats{
		Status:          m.status,
		Interface:       m.activeInterface,
		Duration:        time.Since(m.startTime).String(),
		PacketsCaptured: m.packets,
		BytesCaptured:   m.bytes,
		PacketsPerSec:   pps,
		CurrentChunk:    m.currentChunk,
		QueueDepth:      0, // Can be improved
		AnalyzerWorkers: m.workers,
	}
}

func (m *LiveCaptureManager) SetFilter(filter string) {
	m.mu.Lock()
	m.bpfFilter = filter
	m.mu.Unlock()
}

func (m *LiveCaptureManager) captureLoop(iface string) {
	handle, err := afpacket.NewTPacket(afpacket.OptInterface(iface))
	if err != nil {
		m.mu.Lock()
		m.status = "ERROR"
		m.mu.Unlock()
		log.Printf("Error opening interface %s: %v", iface, err)
		if m.eventEmitter != nil {
			m.eventEmitter("capture.error", map[string]string{"error": err.Error()})
		}
		return
	}
	defer handle.Close()

	// Afpacket does not support SetBPFFilter natively without compiling BPF instructions manually.
	// For simplicity in the prototype, we will just capture everything or use BPF compilation.
	log.Printf("Live capture started on %s without BPF filter in afpacket mode", iface)

	packetSource := gopacket.NewPacketSource(handle, layers.LinkTypeEthernet)
	packetChan := packetSource.Packets()

	queue := make(chan string, 100)

	var wg sync.WaitGroup
	for i := 0; i < m.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range queue {
				if m.eventEmitter != nil {
					m.eventEmitter("analysis.started", map[string]string{"chunk": filepath.Base(path)})
				}
				m.analyzeFunc(path)
			}
		}()
	}

	var currentFile *os.File
	var currentWriter *pcapgo.Writer
	var currentPath string
	chunkIndex := 1
	chunkEndTime := time.Now().Add(time.Duration(m.chunkSeconds) * time.Second)

	rotateChunk := func() error {
		if currentFile != nil {
			currentFile.Close()
			if m.eventEmitter != nil {
				m.eventEmitter("capture.chunk_completed", map[string]string{"chunk": filepath.Base(currentPath)})
				m.eventEmitter("analysis.queued", map[string]string{"chunk": filepath.Base(currentPath)})
			}
			select {
			case queue <- currentPath:
			default:
				log.Printf("Warning: analyzer queue full, dropping chunk %s", currentPath)
			}
		}

		timestamp := time.Now().Format("20060102-150405")
		captureID := fmt.Sprintf("live-capture-%s-%04d", timestamp, chunkIndex)
		chunkIndex++
		
		currentPath = filepath.Join(m.outputDir, fmt.Sprintf("%s.pcap", captureID))

		m.mu.Lock()
		m.currentChunk = filepath.Base(currentPath)
		m.mu.Unlock()

		f, err := os.Create(currentPath)
		if err != nil {
			return err
		}

		currentFile = f
		currentWriter = pcapgo.NewWriter(f)
		if err := currentWriter.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
			return err
		}

		if m.eventEmitter != nil {
			m.eventEmitter("capture.chunk_started", map[string]string{"chunk": filepath.Base(currentPath)})
		}

		chunkEndTime = time.Now().Add(time.Duration(m.chunkSeconds) * time.Second)
		return nil
	}

	if err := rotateChunk(); err != nil {
		log.Printf("Error creating initial chunk: %v", err)
		m.mu.Lock()
		m.status = "ERROR"
		m.mu.Unlock()
		return
	}

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopChan:
			if currentFile != nil {
				currentFile.Close()
				queue <- currentPath
			}
			close(queue)
			wg.Wait()
			return
		case <-ticker.C:
			if time.Now().After(chunkEndTime) {
				if err := rotateChunk(); err != nil {
					log.Printf("Error rotating chunk: %v", err)
				}
			}
			if m.eventEmitter != nil {
				m.mu.Lock()
				m.eventEmitter("capture.packet_stats", map[string]interface{}{
					"packets": m.packets,
					"bytes":   m.bytes,
				})
				m.mu.Unlock()
			}
		case packet, ok := <-packetChan:
			if !ok {
				continue
			}

			if currentWriter != nil {
				currentWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
			}

			m.mu.Lock()
			m.packets++
			m.bytes += len(packet.Data())
			m.mu.Unlock()
		}
	}
}
