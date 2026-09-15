package tlsinspect

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/securemailscope/backend/internal/models"
)

type TSharkInspector struct {
	TSharkPath string
	Timeout    time.Duration
}

func NewTSharkInspector(tsharkPath string, timeout time.Duration) *TSharkInspector {
	if tsharkPath == "" {
		tsharkPath = "tshark"
	}
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	return &TSharkInspector{
		TSharkPath: tsharkPath,
		Timeout:    timeout,
	}
}

func (t *TSharkInspector) Available() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, t.TSharkPath, "-v")
	return cmd.Run() == nil
}

// tsharkFlatJSON matches the structure TShark outputs when using -e field flags:
// fields appear as arrays directly inside "layers", not nested under protocol name.
type tsharkFlatPacketJSON struct {
	Source struct {
		Layers struct {
			TCPStream             []string `json:"tcp.stream"`
			TLSHandshakeType      []string `json:"tls.handshake.type"`
			TLSRecordVersion      []string `json:"tls.record.version"`
			TLSHandshakeVersion   []string `json:"tls.handshake.version"`
			TLSSupportedVersion   []string `json:"tls.handshake.extensions.supported_version"` // TLS 1.3 real version
			TLSCipherSuite        []string `json:"tls.handshake.ciphersuite"`
			TLSServerName         []string `json:"tls.handshake.extensions_server_name"`
			TLSAlertMessage       []string `json:"tls.alert_message"`
		} `json:"layers"`
	} `json:"_source"`
}

// StreamTLSResult holds aggregated TLS info for a single TCP stream
type StreamTLSResult struct {
	StreamID   int
	TLSVersion string
	Cipher     string
	ServerName string
	AlertCount int
	Complete   bool
}

func (t *TSharkInspector) Inspect(pcapPath string) ([]models.TLSInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), t.Timeout)
	defer cancel()

	// Direct argument slice — no shell interpolation. No -2 flag (causes issues with many PCAPs).
	// Filter to ServerHello (type 2) only to get the negotiated TLS version + cipher per stream.
	args := []string{
		"-r", pcapPath,
		"-T", "json",
		"-Y", "tls.handshake.type == 2",  // ServerHello packets only
		"-e", "tcp.stream",
		"-e", "tls.handshake.type",
		"-e", "tls.handshake.version",
		"-e", "tls.record.version",
		"-e", "tls.handshake.ciphersuite",
		"-e", "tls.handshake.extensions_server_name",
		"-e", "tls.handshake.extensions.supported_version", // TLS 1.3 real negotiated version
	}

	cmd := exec.CommandContext(ctx, t.TSharkPath, args...)
	output, err := cmd.Output()
	if err != nil {
		// Try a broader filter as fallback
		return t.inspectBroad(pcapPath)
	}

	if len(output) == 0 || string(output) == "[]\n" {
		return t.inspectBroad(pcapPath)
	}

	return t.parseOutput(output)
}

// inspectBroad falls back to capturing any TLS record packets when ServerHello filter returns nothing
func (t *TSharkInspector) inspectBroad(pcapPath string) ([]models.TLSInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), t.Timeout)
	defer cancel()

	args := []string{
		"-r", pcapPath,
		"-T", "json",
		"-Y", "tls",
		"-e", "tcp.stream",
		"-e", "tls.handshake.type",
		"-e", "tls.handshake.version",
		"-e", "tls.record.version",
		"-e", "tls.handshake.ciphersuite",
		"-e", "tls.handshake.extensions_server_name",
		"-e", "tls.alert_message",
	}

	cmd := exec.CommandContext(ctx, t.TSharkPath, args...)
	output, err := cmd.Output()
	if err != nil || len(output) == 0 {
		return nil, nil
	}

	return t.parseOutput(output)
}

func (t *TSharkInspector) parseOutput(output []byte) ([]models.TLSInfo, error) {
	var packets []tsharkFlatPacketJSON
	if err := json.Unmarshal(output, &packets); err != nil {
		return nil, fmt.Errorf("failed to parse tshark json output: %w", err)
	}

	// Aggregate by TCP stream ID — one TLSInfo per stream
	streamMap := make(map[int]*StreamTLSResult)

	for _, pkt := range packets {
		layers := pkt.Source.Layers

		streamID := 0
		if len(layers.TCPStream) > 0 {
			fmt.Sscanf(layers.TCPStream[0], "%d", &streamID)
		}

		result, exists := streamMap[streamID]
		if !exists {
			result = &StreamTLSResult{StreamID: streamID}
			streamMap[streamID] = result
		}

		// TLS version: prefer supported_version extension (TLS 1.3) > handshake version > record version
		if len(layers.TLSSupportedVersion) > 0 && result.TLSVersion == "" {
			result.TLSVersion = normalizeTLSVersion(layers.TLSSupportedVersion[0])
		}
		if len(layers.TLSHandshakeVersion) > 0 && result.TLSVersion == "" {
			v := normalizeTLSVersion(layers.TLSHandshakeVersion[0])
			if v != "" {
				result.TLSVersion = v
			}
		}
		if result.TLSVersion == "" && len(layers.TLSRecordVersion) > 0 {
			result.TLSVersion = normalizeTLSVersion(layers.TLSRecordVersion[0])
		}

		// Cipher suite
		if len(layers.TLSCipherSuite) > 0 && result.Cipher == "" {
			result.Cipher = formatCipherSuite(layers.TLSCipherSuite[0])
		}

		// SNI
		if len(layers.TLSServerName) > 0 && result.ServerName == "" {
			result.ServerName = layers.TLSServerName[0]
		}

		// Alerts
		if len(layers.TLSAlertMessage) > 0 {
			result.AlertCount++
		}

		result.Complete = true
	}

	// Convert map to slice, sorted by stream ID
	var tlsList []models.TLSInfo
	for _, r := range streamMap {
		tlsInfo := models.TLSInfo{
			Version:            r.TLSVersion,
			CipherSuite:        r.Cipher,
			ServerName:         r.ServerName,
			HandshakeSucceeded: r.AlertCount == 0,
			CertificateSeen:    r.Complete,
			AlertCount:         r.AlertCount,
			StreamID:           r.StreamID,
			Complete:           r.Complete,
		}
		if tlsInfo.Version != "" || tlsInfo.CipherSuite != "" {
			tlsList = append(tlsList, tlsInfo)
		}
	}

	return tlsList, nil
}

func normalizeTLSVersion(ver string) string {
	switch ver {
	case "0x0300":
		return "SSLv3"
	case "0x0301":
		return "TLS 1.0"
	case "0x0302":
		return "TLS 1.1"
	case "0x0303":
		return "TLS 1.2"
	case "0x0304":
		return "TLS 1.3"
	default:
		if strings.HasPrefix(ver, "TLS") || strings.HasPrefix(ver, "SSL") {
			return ver
		}
		return ""
	}
}

func formatCipherSuite(cipherHex string) string {
	if cipherHex == "" {
		return ""
	}
	lower := strings.ToLower(cipherHex)
	switch lower {
	case "0x1301":
		return "TLS_AES_128_GCM_SHA256"
	case "0x1302":
		return "TLS_AES_256_GCM_SHA384"
	case "0x1303":
		return "TLS_CHACHA20_POLY1305_SHA256"
	case "0xc02f":
		return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
	case "0xc030":
		return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
	case "0xc027":
		return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
	case "0xc028":
		return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"
	case "0x009c":
		return "TLS_RSA_WITH_AES_128_GCM_SHA256"
	case "0x009d":
		return "TLS_RSA_WITH_AES_256_GCM_SHA384"
	case "0x002f":
		return "TLS_RSA_WITH_AES_128_CBC_SHA"
	case "0x0035":
		return "TLS_RSA_WITH_AES_256_CBC_SHA"
	case "0x000a":
		return "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
	case "0x0005":
		return "TLS_RSA_WITH_RC4_128_SHA"
	default:
		return cipherHex
	}
}

func AssessForwardSecrecy(tlsVersion, cipher string) models.ForwardSecrecyStatus {
	if tlsVersion == "TLS 1.3" {
		// TLS 1.3 always uses ephemeral key exchange
		return models.FSYes
	}
	if cipher == "" {
		return models.FSUnknown
	}
	upperCipher := strings.ToUpper(cipher)
	if strings.Contains(upperCipher, "ECDHE") || strings.Contains(upperCipher, "_DHE_") || strings.Contains(upperCipher, "DHE_RSA") {
		return models.FSYes
	}
	if strings.Contains(upperCipher, "RSA_WITH") || strings.Contains(upperCipher, "3DES") ||
		strings.Contains(upperCipher, "RC4") || strings.Contains(upperCipher, "DES_CBC") {
		return models.FSNo
	}
	return models.FSUnknown
}
