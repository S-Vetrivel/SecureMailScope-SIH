package risk

import (
	"testing"

	"github.com/securemailscope/backend/internal/models"
)

func TestRiskEngineWeakTLS(t *testing.T) {
	engine := NewEngine(DefaultPolicy())
	session := models.EmailSession{
		ID:       "S001",
		Protocol: models.ProtocolSMTP,
		StartTLS: models.StartTLSInfo{Supported: true, Requested: true, Accepted: true, TLSEstablished: true},
		TLS: &models.TLSInfo{
			Version:            "TLS 1.0",
			CipherSuite:        "TLS_RSA_WITH_AES_128_GCM_SHA256",
			HandshakeCompleted: true,
			TLSObserved:        true,
		},
		ForwardSecrecy: models.FSNo,
	}

	findings := engine.Assess(session)
	if len(findings) == 0 {
		t.Fatalf("Expected findings for weak TLS 1.0 and lack of PFS")
	}

	foundTLS10 := false
	for _, f := range findings {
		if f.Category == "TLS" && f.Severity == models.SeverityCritical {
			foundTLS10 = true
		}
	}

	if !foundTLS10 {
		t.Errorf("Expected Critical TLS 1.0 finding")
	}
}

func TestRiskEngineGreaseCipher(t *testing.T) {
	engine := NewEngine(DefaultPolicy())
	session := models.EmailSession{
		ID:       "S002",
		Protocol: models.ProtocolSMTP,
		StartTLS: models.StartTLSInfo{Supported: true, Requested: true, Accepted: true, TLSEstablished: true},
		TLS: &models.TLSInfo{
			Version:            "TLS 1.2",
			CipherSuite:        "0x6a6a",
			HandshakeCompleted: false,
			CertificateSeen:    false,
			TLSObserved:        true,
		},
	}
	findings := engine.Assess(session)
	for _, f := range findings {
		if f.Category == "CIPHER" || f.Category == "KEY_EXCHANGE" {
			t.Errorf("Unexpected finding for UNKNOWN/GREASE cipher: %s", f.Title)
		}
	}
}

func TestRiskEngineLegitimateCases(t *testing.T) {
	engine := NewEngine(DefaultPolicy())
	tests := []struct {
		name        string
		tls         models.TLSInfo
		expectPFS   bool
		expectWeak  bool
	}{
		{
			name: "TLS 1.3 AES_128_GCM",
			tls: models.TLSInfo{Version: "TLS 1.3", CipherSuite: "TLS_AES_128_GCM_SHA256", HandshakeCompleted: true},
			expectPFS: true, expectWeak: false,
		},
		{
			name: "TLS 1.3 CHACHA20",
			tls: models.TLSInfo{Version: "TLS 1.3", CipherSuite: "TLS_CHACHA20_POLY1305_SHA256", HandshakeCompleted: true},
			expectPFS: true, expectWeak: false,
		},
		{
			name: "TLS 1.2 ECDHE",
			tls: models.TLSInfo{Version: "TLS 1.2", CipherSuite: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", HandshakeCompleted: true},
			expectPFS: true, expectWeak: false,
		},
		{
			name: "TLS 1.2 RSA Static",
			tls: models.TLSInfo{Version: "TLS 1.2", CipherSuite: "TLS_RSA_WITH_AES_128_GCM_SHA256", HandshakeCompleted: true},
			expectPFS: false, expectWeak: false,
		},
		{
			name: "Unknown Cipher ID",
			tls: models.TLSInfo{Version: "TLS 1.2", CipherSuite: "UNKNOWN", HandshakeCompleted: true},
			expectPFS: true, expectWeak: false, // PFS finding should not fire if unknown
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := models.EmailSession{
				ID: "T001",
				StartTLS: models.StartTLSInfo{Supported: true, Requested: true, Accepted: true, TLSEstablished: true},
				TLS: &tt.tls,
			}
			findings := engine.Assess(session)
			hasPFSFinding := false
			hasWeakCipher := false
			for _, f := range findings {
				if f.Category == "KEY_EXCHANGE" {
					hasPFSFinding = true
				}
				if f.Category == "CIPHER" && f.Severity == models.SeverityCritical {
					hasWeakCipher = true
				}
			}
			if tt.expectPFS && hasPFSFinding {
				t.Errorf("Unexpected PFS finding for %s", tt.name)
			}
			if !tt.expectPFS && !hasPFSFinding {
				t.Errorf("Expected PFS finding for %s", tt.name)
			}
			if tt.expectWeak && !hasWeakCipher {
				t.Errorf("Expected Weak cipher finding for %s", tt.name)
			}
			if !tt.expectWeak && hasWeakCipher {
				t.Errorf("Unexpected Weak cipher finding for %s", tt.name)
			}
		})
	}
}

