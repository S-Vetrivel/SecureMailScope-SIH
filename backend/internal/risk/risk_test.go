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
			HandshakeSucceeded: true,
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
