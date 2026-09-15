// Package reassembly provides TCP stream reassembly for email protocol traffic.
// It uses gopacket's tcpassembly to reconstruct TCP streams and detect
// email protocols (SMTP, IMAP, POP3), STARTTLS negotiation, and TLS handshakes.
package reassembly

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	"github.com/securemailscope/parser/internal/models"
	"github.com/securemailscope/parser/internal/tlsparser"
)

// Well-known email ports for protocol detection
var emailPorts = map[uint16]string{
	25:  "SMTP",
	465: "SMTPS",
	587: "SMTP",  // Submission (STARTTLS)
	143: "IMAP",
	993: "IMAPS",
	110: "POP3",
	995: "POP3S",
}

// Ports that use direct TLS (no STARTTLS negotiation needed)
var directTLSPorts = map[uint16]bool{
	465: true, // SMTPS
	993: true, // IMAPS
	995: true, // POP3S
}

// SessionCollector aggregates parsed email sessions from concurrent goroutines.
type SessionCollector struct {
	mu       sync.Mutex
	sessions []*models.EmailSession
}

// AddSession safely adds a parsed session to the collector.
func (sc *SessionCollector) AddSession(s *models.EmailSession) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.sessions = append(sc.sessions, s)
}

// GetSessions returns all collected sessions.
func (sc *SessionCollector) GetSessions() []*models.EmailSession {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	result := make([]*models.EmailSession, len(sc.sessions))
	copy(result, sc.sessions)
	return result
}

// EmailStreamFactory creates new email stream handlers for TCP reassembly.
type EmailStreamFactory struct {
	collector *SessionCollector
	wg        sync.WaitGroup
}

// NewEmailStreamFactory creates a factory that feeds parsed sessions to the collector.
func NewEmailStreamFactory(collector *SessionCollector) *EmailStreamFactory {
	return &EmailStreamFactory{
		collector: collector,
	}
}

// Wait blocks until all stream goroutines have completed.
func (f *EmailStreamFactory) Wait() {
	f.wg.Wait()
}

// New implements tcpassembly.StreamFactory. It's called for each new TCP stream.
func (f *EmailStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	rs := tcpreader.NewReaderStream()

	srcPort := binary.BigEndian.Uint16(transport.Src().Raw())
	dstPort := binary.BigEndian.Uint16(transport.Dst().Raw())

	// Determine if this is an email-related stream
	protocol, port, isEmail := detectEmailProtocol(srcPort, dstPort)

	if isEmail {
		f.wg.Add(1)
		stream := &emailStream{
			reader:    &rs,
			srcIP:     net.Src().String(),
			dstIP:     net.Dst().String(),
			srcPort:   srcPort,
			dstPort:   dstPort,
			protocol:  protocol,
			emailPort: port,
			collector: f.collector,
			wg:        &f.wg,
			isServer:  srcPort == port, // Server sends FROM the well-known port
		}
		go stream.run()
	} else {
		// Not an email stream — discard data
		f.wg.Add(1)
		go func() {
			defer f.wg.Done()
			tcpreader.DiscardBytesToEOF(&rs)
		}()
	}

	return &rs
}

// detectEmailProtocol checks if either port matches a known email service.
func detectEmailProtocol(srcPort, dstPort uint16) (protocol string, port uint16, isEmail bool) {
	if p, ok := emailPorts[dstPort]; ok {
		return p, dstPort, true
	}
	if p, ok := emailPorts[srcPort]; ok {
		return p, srcPort, true
	}
	return "", 0, false
}

// emailStream processes a single direction of a TCP stream for email protocol data.
type emailStream struct {
	reader    *tcpreader.ReaderStream
	srcIP     string
	dstIP     string
	srcPort   uint16
	dstPort   uint16
	protocol  string
	emailPort uint16
	collector *SessionCollector
	wg        *sync.WaitGroup
	isServer  bool
}

// run processes the stream data, detecting STARTTLS and parsing TLS handshakes.
func (s *emailStream) run() {
	defer s.wg.Done()

	session := &models.EmailSession{
		SessionID:    fmt.Sprintf("%s:%d-%s:%d", s.srcIP, s.srcPort, s.dstIP, s.dstPort),
		SrcIP:        s.srcIP,
		SrcPort:      s.srcPort,
		DstIP:        s.dstIP,
		DstPort:      s.dstPort,
		Protocol:     s.protocol,
		ProtocolPort: s.emailPort,
		StartTime:    time.Now(),
		IsEncrypted:  directTLSPorts[s.emailPort],
	}

	buf := bufio.NewReaderSize(s.reader, 16384)

	if directTLSPorts[s.emailPort] {
		// Direct TLS port — immediately parse TLS records
		s.parseTLSStream(buf, session)
	} else {
		// Plaintext port — look for STARTTLS, then switch to TLS parsing
		s.parsePlaintextStream(buf, session)
	}

	session.EndTime = time.Now()

	// Only add sessions that have meaningful data
	if session.TLSHandshake != nil || session.HasSTARTTLS || session.RawBanner != "" {
		s.collector.AddSession(session)
	}
}

// parsePlaintextStream reads plaintext email protocol data looking for STARTTLS.
func (s *emailStream) parsePlaintextStream(buf *bufio.Reader, session *models.EmailSession) {
	for {
		line, err := buf.ReadString('\n')
		if err != nil {
			return
		}

		line = strings.TrimSpace(line)

		// Capture the first banner line
		if session.RawBanner == "" && line != "" {
			session.RawBanner = line
			// Refine protocol detection from banner
			s.refineProtocol(line, session)
		}

		// Detect STARTTLS command or response
		upper := strings.ToUpper(line)
		if strings.Contains(upper, "STARTTLS") {
			session.HasSTARTTLS = true
			session.IsEncrypted = true
			log.Printf("[STARTTLS] Detected in %s session %s", session.Protocol, session.SessionID)

			// After STARTTLS response (220 for SMTP, OK for IMAP), TLS begins
			if s.isServer && (strings.HasPrefix(line, "220") || strings.Contains(upper, "OK")) {
				s.parseTLSStream(buf, session)
				return
			}
		}
	}
}

// refineProtocol updates protocol based on server banner content.
func (s *emailStream) refineProtocol(banner string, session *models.EmailSession) {
	upper := strings.ToUpper(banner)
	switch {
	case strings.Contains(upper, "SMTP") || strings.HasPrefix(banner, "220"):
		if session.Protocol == "" {
			session.Protocol = "SMTP"
		}
	case strings.Contains(upper, "IMAP") || strings.HasPrefix(banner, "* OK"):
		session.Protocol = "IMAP"
	case strings.Contains(upper, "POP3") || strings.HasPrefix(banner, "+OK"):
		session.Protocol = "POP3"
	}
}

// parseTLSStream reads and parses TLS records from the stream.
func (s *emailStream) parseTLSStream(buf *bufio.Reader, session *models.EmailSession) {
	parser := tlsparser.NewParser()

	for i := 0; i < 20; i++ { // Parse up to 20 TLS records (enough for a full handshake)
		// Read TLS record header (5 bytes)
		header, err := buf.Peek(5)
		if err != nil {
			break
		}

		// Validate TLS content type
		contentType := header[0]
		if contentType < 20 || contentType > 23 {
			break // Not a valid TLS record
		}

		// Get record length
		recordLen := binary.BigEndian.Uint16(header[3:5])
		if recordLen > 16384 { // TLS max record size
			break
		}

		// Read the full record
		fullRecord := make([]byte, 5+int(recordLen))
		_, err = io.ReadFull(buf, fullRecord)
		if err != nil {
			break
		}

		// Process the record
		if parseErr := parser.ProcessRecord(fullRecord, s.isServer); parseErr != nil {
			log.Printf("[TLS] Parse warning for %s: %v", session.SessionID, parseErr)
		}
	}

	// Get the parsed results
	handshake, certs := parser.GetResult()

	if handshake.NegotiatedCipher != "" || handshake.ClientHelloVersion != "" || handshake.ServerHelloVersion != "" {
		session.TLSHandshake = handshake
	}
	if len(certs) > 0 {
		session.Certificates = certs
	}
}
