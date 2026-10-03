package capture

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
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

	stopChan   chan struct{}
	cancelFunc context.CancelFunc

	chunkSeconds int
	workers      int
	outputDir    string
	bpfFilter    string

	analyzeFunc  func(pcapPath string)
	eventEmitter func(eventType string, data interface{})
}

func NewLiveCaptureManager(outputDir string, analyzeFunc func(string), eventEmitter func(string, interface{})) *LiveCaptureManager {
	_ = os.MkdirAll(outputDir, 0755)
	// Also pre-create /tmp capture dir (world-writable, works across all filesystems
	// including NTFS where chmod doesn't work)
	_ = os.MkdirAll("/tmp/securemailscope-live", 0777)

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
		bpfFilter:    "tcp port 25 or tcp port 465 or tcp port 587 or tcp port 110 or tcp port 995 or tcp port 143 or tcp port 993",
	}
}

func (m *LiveCaptureManager) GetInterfaces() ([]Interface, error) {
	res := []Interface{
		// 'any' captures on ALL interfaces simultaneously - best for finding email traffic
		// regardless of which IP the client connects to
		{Name: "any", Type: "all", Up: true},
	}
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

	if iface == "" {
		iface = "any"
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

	select {
	case <-m.stopChan:
	default:
		close(m.stopChan)
	}

	if m.cancelFunc != nil {
		m.cancelFunc()
	}

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
		QueueDepth:      0,
		AnalyzerWorkers: m.workers,
	}
}

func (m *LiveCaptureManager) SetFilter(filter string) {
	m.mu.Lock()
	m.bpfFilter = filter
	m.mu.Unlock()
}

// captureLoop captures using dumpcap (low-level wireshark capture tool).
// dumpcap is owned by root and executable by root, so it works fine when
// the backend runs as root (sudo). It does NOT drop privileges like tshark does.
// Each chunk runs for chunkSeconds, then the PCAP is enqueued for analysis.
func (m *LiveCaptureManager) captureLoop(iface string) {
	log.Printf("[CAPTURE] Starting live capture on %s using dumpcap (chunk=%ds)", iface, m.chunkSeconds)

	// Spawn analysis worker goroutines
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

	chunkIndex := 1

	for {
		// Check stop signal
		select {
		case <-m.stopChan:
			log.Printf("[CAPTURE] Stop signal received, draining queue and exiting")
			close(queue)
			wg.Wait()
			return
		default:
		}

		// Name this chunk
		timestamp := time.Now().Format("20060102-150405")
		captureID := fmt.Sprintf("live-capture-%s-%04d", timestamp, chunkIndex)
		chunkIndex++
		currentPath := filepath.Join(m.outputDir, captureID+".pcap")

		m.mu.Lock()
		m.currentChunk = filepath.Base(currentPath)
		m.mu.Unlock()

		if m.eventEmitter != nil {
			m.eventEmitter("capture.chunk_started", map[string]string{"chunk": filepath.Base(currentPath)})
		}

		// Use dumpcap directly — it's owned by root and works when backend runs as sudo.
		// -i  = interface
		// -a duration:N = stop after N seconds
		// -w  = output file (pcap format, not pcapng)
		// -q  = quiet (no per-packet console output)
		// -P  = use pcap format (not pcapng, for compatibility with our reader)
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(m.chunkSeconds+5)*time.Second)
		m.mu.Lock()
		m.cancelFunc = cancel
		m.mu.Unlock()

		// Write to /tmp first (always world-writable, works on NTFS/fuseblk
		// where chmod doesn't work). dumpcap drops privs before writing.
		tmpPath := fmt.Sprintf("/tmp/securemailscope-live/%s.pcap", captureID)

		// Use tcpdump directly via bash wrapper to ensure graceful SIGTERM after chunkSeconds.
		// -Z root ensures it doesn't drop privileges which causes issues with tailscale0
		// -U makes it packet-buffered so it writes immediately.
		m.mu.Lock()
		bpf := m.bpfFilter
		m.mu.Unlock()

		bashScript := fmt.Sprintf(`
			/usr/bin/tcpdump -i "%s" -w "%s" -s 0 -Z root -U -nn -q %s &
			TCPDUMP_PID=$!
			sleep %d
			kill -TERM $TCPDUMP_PID 2>/dev/null
			wait $TCPDUMP_PID 2>/dev/null
			exit 0
		`, iface, tmpPath, bpf, m.chunkSeconds)

		cmd := exec.CommandContext(ctx, "bash", "-c", bashScript)
		
		log.Printf("[LIVE] requested interface=%s", iface)
		log.Printf("[LIVE] actual capture interface=%s", iface)
		log.Printf("[LIVE] filter=%s", bpf)
		log.Printf("[LIVE] exact command: %v", cmd.Args)

		// Capture stderr separately since tcpdump writes status there
		out, err := cmd.CombinedOutput()
		cancel()

		if err != nil {
			if ctx.Err() == context.DeadlineExceeded {
				log.Printf("[CAPTURE] tcpdump chunk timed out unexpectedly (expected %ds)", m.chunkSeconds)
			} else {
				log.Printf("[CAPTURE] tcpdump error: %v | output: %s", err, string(out))
				// Brief pause before retry to avoid tight error loop
				time.Sleep(2 * time.Second)
				continue
			}
		}

		// Stat the tmp file first
		tmpInfo, statErr := os.Stat(tmpPath)
		if statErr != nil || tmpInfo.Size() == 0 {
			log.Printf("[CAPTURE] tcpdump failed to start or write PCAP header (statErr=%v). Check interface and permissions.", statErr)
			m.mu.Lock()
			m.status = "ERROR"
			m.mu.Unlock()
			os.Remove(tmpPath)
			
			if m.eventEmitter != nil {
				m.eventEmitter("capture.error", map[string]string{"error": "tcpdump failed to start"})
			}
			return
		}
		
		if tmpInfo.Size() <= 24 {
			log.Printf("[CAPTURE] Chunk %s is empty (size=%d), skipping", filepath.Base(currentPath), tmpInfo.Size())
			os.Remove(tmpPath)
			continue
		}

		// Move from /tmp to the final outputDir (copy + delete since cross-device)
		if err := moveFile(tmpPath, currentPath); err != nil {
			log.Printf("[CAPTURE] Failed to move %s → %s: %v", tmpPath, currentPath, err)
			os.Remove(tmpPath)
			continue
		}

		info, _ := os.Stat(currentPath)

		// Get exact packet count using tcpdump
		countCmd := exec.Command("bash", "-c", fmt.Sprintf("/usr/bin/tcpdump -nn -r %s 2>/dev/null | wc -l", currentPath))
		countOut, _ := countCmd.Output()
		exactPackets := 0
		fmt.Sscanf(strings.TrimSpace(string(countOut)), "%d", &exactPackets)

		log.Printf("[CAPTURE] Chunk %s ready: %d packets, %d bytes", filepath.Base(currentPath), exactPackets, info.Size())

		m.mu.Lock()
		m.bytes += int(info.Size())
		m.packets += exactPackets
		m.mu.Unlock()

		if m.eventEmitter != nil {
			m.eventEmitter("capture.packet_stats", map[string]interface{}{
				"packets": m.packets,
				"bytes":   m.bytes,
			})
			m.eventEmitter("capture.chunk_completed", map[string]string{"chunk": filepath.Base(currentPath)})
			m.eventEmitter("analysis.queued", map[string]string{"chunk": filepath.Base(currentPath)})
		}

		// Enqueue for analysis — non-blocking, drop if queue full
		select {
		case queue <- currentPath:
		default:
			log.Printf("[CAPTURE] Warning: analyzer queue full, dropping %s", filepath.Base(currentPath))
		}
	}
}

// moveFile moves src to dst, handling cross-device moves (e.g. /tmp → NTFS mount).
// os.Rename fails across devices, so we fall back to copy+delete.
func moveFile(src, dst string) error {
	// Try atomic rename first (works if same filesystem)
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	// Fall back: copy then remove
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}

	if _, err = io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(dst)
		return err
	}
	if err = out.Close(); err != nil {
		os.Remove(dst)
		return err
	}
	return os.Remove(src)
}
