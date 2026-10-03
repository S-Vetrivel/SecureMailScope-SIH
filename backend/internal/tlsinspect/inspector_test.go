package tlsinspect

import (
	"testing"
	"github.com/securemailscope/backend/internal/models"
)

func TestParseOutputRegression(t *testing.T) {
	// Simulated tshark JSON output based on the user's PCAP description
	mockOutput := `[
		{
			"_source": {
				"layers": {
					"tcp.stream": ["0"],
					"tls.handshake.type": ["1"],
					"tls.record.version": ["0x0301"],
					"tls.handshake.version": ["0x0303"],
					"tls.handshake.extensions.supported_version": ["0x0a0a", "0x0304", "0x0303"],
					"tls.handshake.ciphersuite": ["0x0a0a", "0x1302", "0x1303"],
					"tls.handshake.extensions_key_share_group": ["0x7a7a", "0x001d"]
				}
			}
		},
		{
			"_source": {
				"layers": {
					"tcp.stream": ["0"],
					"tls.handshake.type": ["2"],
					"tls.record.version": ["0x0303"],
					"tls.handshake.version": ["0x0303"],
					"tls.handshake.extensions.supported_version": ["0x0304"],
					"tls.handshake.ciphersuite": ["0x1302"],
					"tls.handshake.extensions_key_share_group": ["0x001d"]
				}
			}
		}
	]`

	inspector := &TSharkInspector{}
	infos, err := inspector.parseOutput([]byte(mockOutput))
	if err != nil {
		t.Fatalf("parseOutput failed: %v", err)
	}

	if len(infos) != 1 {
		t.Fatalf("expected 1 TLSInfo, got %d", len(infos))
	}

	info := infos[0]

	if info.Version != "TLS 1.3" {
		t.Errorf("Expected TLS version 'TLS 1.3', got '%s'", info.Version)
	}

	if info.CipherSuite != "TLS_AES_256_GCM_SHA384" {
		t.Errorf("Expected cipher suite 'TLS_AES_256_GCM_SHA384', got '%s'", info.CipherSuite)
	}

	if info.KeyExchangeGroup != "X25519" {
		t.Errorf("Expected key exchange group 'X25519', got '%s'", info.KeyExchangeGroup)
	}
}

func TestAssessForwardSecrecy(t *testing.T) {
	// TLS 1.3 -> Yes
	if fs := AssessForwardSecrecy("TLS 1.3", "TLS_AES_256_GCM_SHA384", "X25519"); fs != models.FSYes {
		t.Errorf("Expected YES for TLS 1.3, got %s", fs)
	}
	// Explicit X25519 -> Yes
	if fs := AssessForwardSecrecy("TLS 1.2", "UNKNOWN", "X25519"); fs != models.FSYes {
		t.Errorf("Expected YES for X25519, got %s", fs)
	}
}
