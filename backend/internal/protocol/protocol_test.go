package protocol

import (
	"testing"

	"github.com/securemailscope/backend/internal/models"
	"github.com/securemailscope/backend/internal/session"
)

func TestDetectorSMTP(t *testing.T) {
	detector := NewDetector()
	res := detector.Detect(48322, 587, []byte("220 mail.example.com ESMTP\r\nEHLO client.local\r\n250-STARTTLS\r\n"))

	if res.Protocol != models.ProtocolSMTP {
		t.Errorf("Expected SMTP protocol, got %s", res.Protocol)
	}
	if res.Confidence < 0.8 {
		t.Errorf("Expected high confidence, got %f", res.Confidence)
	}
}

func TestDetectorIMAP(t *testing.T) {
	detector := NewDetector()
	res := detector.Detect(51200, 143, []byte("* OK IMAP4rev1 Service Ready\r\n. CAPABILITY\r\n"))

	if res.Protocol != models.ProtocolIMAP {
		t.Errorf("Expected IMAP protocol, got %s", res.Protocol)
	}
}

func TestDetectorPOP3(t *testing.T) {
	detector := NewDetector()
	res := detector.Detect(51201, 110, []byte("+OK POP3 server ready\r\nSTLS\r\n"))

	if res.Protocol != models.ProtocolPOP3 {
		t.Errorf("Expected POP3 protocol, got %s", res.Protocol)
	}
}

func TestStartTLSStateSMTP(t *testing.T) {
	analyzer := NewTimelineAnalyzer()
	
	stream := &session.ReassembledStream{
		Chunks: []session.PayloadChunk{
			{IsClient: false, Data: []byte("220 mail.test ESMTP\r\n250-STARTTLS\r\n")},
			{IsClient: true, Data: []byte("EHLO test\r\n")},
			{IsClient: false, Data: []byte("220 Go Ahead\r\n")},
			{IsClient: true, Data: []byte("STARTTLS\r\n")},
			{IsClient: false, Data: []byte("220 Ready to start TLS\r\n")},
			{IsClient: true, Data: []byte("\x16\x03\x01\x00\x05\x01")},
		},
	}

	_, info := analyzer.Analyze(models.ProtocolSMTP, stream)

	if !info.Supported {
		t.Errorf("Expected STARTTLS supported = true")
	}
	if !info.Requested {
		t.Errorf("Expected STARTTLS requested = true")
	}
	if !info.Accepted {
		t.Errorf("Expected STARTTLS accepted = true")
	}
	if !info.TLSEstablished {
		t.Errorf("Expected TLS established = true")
	}
}
