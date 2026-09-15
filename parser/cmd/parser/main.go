// SecureMailScope PCAP Parser
//
// High-performance Go-based parser that reads PCAP files containing email traffic
// (SMTP, IMAP, POP3), reconstructs TCP streams, parses TLS handshakes, extracts
// X.509 certificates, and outputs structured JSON for the AI risk engine.
//
// Usage:
//
//	parser --pcap <file.pcap> --output <sessions.json>
//	parser --pcap <dir_with_pcaps> --output <sessions.json>
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/google/gopacket/tcpassembly"
	"github.com/securemailscope/parser/internal/models"
	"github.com/securemailscope/parser/internal/reassembly"
)

func main() {
	pcapPath := flag.String("pcap", "", "Path to PCAP file or directory containing PCAP files")
	outputPath := flag.String("output", "sessions.json", "Output JSON file path")
	verbose := flag.Bool("verbose", false, "Enable verbose logging")
	flag.Parse()

	if *pcapPath == "" {
		fmt.Fprintf(os.Stderr, "Usage: parser --pcap <file_or_dir> [--output <file.json>] [--verbose]\n")
		os.Exit(1)
	}

	if !*verbose {
		log.SetOutput(io.Discard)
	}

	// Collect PCAP file paths
	pcapFiles, err := collectPCAPFiles(*pcapPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if len(pcapFiles) == 0 {
		fmt.Fprintf(os.Stderr, "No PCAP files found at: %s\n", *pcapPath)
		os.Exit(1)
	}

	fmt.Printf("SecureMailScope Parser v1.0\n")
	fmt.Printf("Processing %d PCAP file(s)...\n\n", len(pcapFiles))

	// Process all PCAPs
	collector := &reassembly.SessionCollector{}
	totalPackets := 0

	for _, f := range pcapFiles {
		n, err := processPCAP(f, collector)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to process %s: %v\n", f, err)
			continue
		}
		totalPackets += n
		fmt.Printf("  ✓ %s (%d packets)\n", filepath.Base(f), n)
	}

	sessions := collector.GetSessions()

	// Build output
	output := models.AnalysisOutput{
		AnalysisID:   fmt.Sprintf("analysis_%d", time.Now().UnixMilli()),
		PcapFile:     *pcapPath,
		ParsedAt:     time.Now(),
		TotalPackets: totalPackets,
		TotalStreams:  len(sessions),
		Sessions:     sessions,
	}

	// Write JSON output
	jsonData, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(*outputPath, jsonData, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing output: %v\n", err)
		os.Exit(1)
	}

	// Print summary
	fmt.Printf("\n=== Analysis Summary ===\n")
	fmt.Printf("Total packets processed: %d\n", totalPackets)
	fmt.Printf("Email sessions found:    %d\n", len(sessions))

	// Count by protocol
	protoCounts := map[string]int{}
	tlsVersionCounts := map[string]int{}
	issueCount := 0

	for _, s := range sessions {
		protoCounts[s.Protocol]++
		if s.TLSHandshake != nil {
			tlsVersionCounts[s.TLSHandshake.NegotiatedVersion]++
		}
		for _, c := range s.Certificates {
			if c.IsExpired || c.IsWeakKey || c.IsWeakSignature || c.IsSelfSigned {
				issueCount++
			}
		}
	}

	for proto, count := range protoCounts {
		fmt.Printf("  %s sessions: %d\n", proto, count)
	}
	for ver, count := range tlsVersionCounts {
		fmt.Printf("  %s: %d sessions\n", ver, count)
	}
	if issueCount > 0 {
		fmt.Printf("  ⚠ Certificate issues: %d\n", issueCount)
	}

	fmt.Printf("\nOutput written to: %s\n", *outputPath)
}

// processPCAP opens a PCAP file, feeds packets to the TCP assembler, and returns packet count.
func processPCAP(filePath string, collector *reassembly.SessionCollector) (int, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return 0, fmt.Errorf("failed to open PCAP file: %w", err)
	}
	defer f.Close()

	handle, err := pcapgo.NewReader(f)
	if err != nil {
		return 0, fmt.Errorf("failed to create PCAP reader: %w", err)
	}

	// Create TCP assembler
	factory := reassembly.NewEmailStreamFactory(collector)
	pool := tcpassembly.NewStreamPool(factory)
	assembler := tcpassembly.NewAssembler(pool)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetCount := 0

	for packet := range packetSource.Packets() {
		packetCount++

		// Get network layer
		networkLayer := packet.NetworkLayer()
		if networkLayer == nil {
			continue
		}

		// Get TCP layer
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			continue
		}

		tcp, ok := tcpLayer.(*layers.TCP)
		if !ok {
			continue
		}

		// Feed to assembler
		assembler.AssembleWithTimestamp(
			networkLayer.NetworkFlow(),
			tcp,
			packet.Metadata().Timestamp,
		)
	}

	// Flush remaining streams
	assembler.FlushAll()
	factory.Wait()

	return packetCount, nil
}

// collectPCAPFiles finds all PCAP files at the given path (file or directory).
func collectPCAPFiles(path string) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("path not found: %s", path)
	}

	if !info.IsDir() {
		return []string{path}, nil
	}

	var files []string
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := strings.ToLower(entry.Name())
		if strings.HasSuffix(name, ".pcap") || strings.HasSuffix(name, ".pcapng") {
			files = append(files, filepath.Join(path, entry.Name()))
		}
	}

	return files, nil
}
