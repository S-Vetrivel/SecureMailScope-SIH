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
			IPSrc                 []string `json:"ip.src"`
			IPDst                 []string `json:"ip.dst"`
			IPv6Src               []string `json:"ipv6.src"`
			IPv6Dst               []string `json:"ipv6.dst"`
			TCPSrcPort            []string `json:"tcp.srcport"`
			TCPDstPort            []string `json:"tcp.dstport"`
			TLSRecordContentType  []string `json:"tls.record.content_type"`
			TLSHandshakeType      []string `json:"tls.handshake.type"`
			TLSRecordVersion      []string `json:"tls.record.version"`
			TLSHandshakeVersion   []string `json:"tls.handshake.version"`
			TLSSupportedVersion   []string `json:"tls.handshake.extensions.supported_version"` // TLS 1.3 real version
			TLSCipherSuite        []string `json:"tls.handshake.ciphersuite"`
			TLSServerName         []string `json:"tls.handshake.extensions_server_name"`
			TLSALPN               []string `json:"tls.handshake.extensions_alpn_str"`
			TLSKeyShareGroup      []string `json:"tls.handshake.extensions_key_share_group"`
			TLSSigHashAlg         []string `json:"tls.handshake.sig_hash_alg"`
			TLSCertificate        []string `json:"tls.handshake.certificate"`
			TLSAlertMessage       []string `json:"tls.alert_message"`
		} `json:"layers"`
	} `json:"_source"`
}

// StreamTLSResult holds aggregated TLS info for a single TCP stream
type StreamTLSResult struct {
	StreamID   int
	SrcIP      string
	DstIP      string
	SrcPort    string
	DstPort    string
	TLSVersion string
	Cipher     string
	ServerName     string
	ALPN           string
	KeyExchangeGrp string
	SigAlg         string
	Certificates   []string // Hex encoded DER
	AlertCount     int
	TLSObserved    bool
	ServerHelloSeen bool
	CertificateSeen bool
	HandshakeFailed bool
	HandshakeCompleted bool
	AppDataObserved bool
}

func (t *TSharkInspector) Inspect(pcapPath string) ([]models.TLSInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), t.Timeout)
	defer cancel()

	// Filter to any TLS packets to get full handshake + application data state
	args := []string{
		"-r", pcapPath,
		"-T", "json",
		"-Y", "tls",
		"-e", "tcp.stream",
		"-e", "ip.src",
		"-e", "ip.dst",
		"-e", "ipv6.src",
		"-e", "ipv6.dst",
		"-e", "tcp.srcport",
		"-e", "tcp.dstport",
		"-e", "tls.record.content_type",
		"-e", "tls.handshake.type",
		"-e", "tls.handshake.version",
		"-e", "tls.record.version",
		"-e", "tls.handshake.ciphersuite",
		"-e", "tls.handshake.extensions_server_name",
		"-e", "tls.handshake.extensions_alpn_str",
		"-e", "tls.handshake.extensions_key_share_group",
		"-e", "tls.handshake.sig_hash_alg",
		"-e", "tls.handshake.certificate",
		"-e", "tls.handshake.extensions.supported_version", // TLS 1.3 real negotiated version
		"-e", "tls.alert_message",
	}

	cmd := exec.CommandContext(ctx, t.TSharkPath, args...)
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	if len(output) == 0 || string(output) == "[]\n" {
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

		if len(layers.IPSrc) > 0 {
			result.SrcIP = layers.IPSrc[0]
		} else if len(layers.IPv6Src) > 0 {
			result.SrcIP = layers.IPv6Src[0]
		}
		if len(layers.IPDst) > 0 {
			result.DstIP = layers.IPDst[0]
		} else if len(layers.IPv6Dst) > 0 {
			result.DstIP = layers.IPv6Dst[0]
		}
		if len(layers.TCPSrcPort) > 0 {
			result.SrcPort = layers.TCPSrcPort[0]
		}
		if len(layers.TCPDstPort) > 0 {
			result.DstPort = layers.TCPDstPort[0]
		}
		result.TLSObserved = true

		for _, ht := range layers.TLSHandshakeType {
			if ht == "2" {
				result.ServerHelloSeen = true
			} else if ht == "11" {
				result.CertificateSeen = true
			} else if ht == "20" {
				result.HandshakeCompleted = true
			}
		}

		for _, ct := range layers.TLSRecordContentType {
			if ct == "23" {
				result.AppDataObserved = true
			}
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
		
		if len(layers.TLSALPN) > 0 && result.ALPN == "" {
			result.ALPN = layers.TLSALPN[0]
		}
		
		if len(layers.TLSKeyShareGroup) > 0 && result.KeyExchangeGrp == "" {
			result.KeyExchangeGrp = layers.TLSKeyShareGroup[0]
		}
		
		if len(layers.TLSSigHashAlg) > 0 && result.SigAlg == "" {
			result.SigAlg = layers.TLSSigHashAlg[0]
		}
		
		if len(layers.TLSCertificate) > 0 {
			result.Certificates = append(result.Certificates, layers.TLSCertificate...)
		}

		// Alerts
		if len(layers.TLSAlertMessage) > 0 {
			result.AlertCount++
		}
	}

	// Convert map to slice, sorted by stream ID
	var tlsList []models.TLSInfo
	for _, r := range streamMap {
		var srcPort, dstPort uint16
		fmt.Sscanf(r.SrcPort, "%d", &srcPort)
		fmt.Sscanf(r.DstPort, "%d", &dstPort)

		tlsInfo := models.TLSInfo{
			Version:            r.TLSVersion,
			CipherSuite:        r.Cipher,
			ServerName:         r.ServerName,
			ALPN:               r.ALPN,
			KeyExchangeGroup:   r.KeyExchangeGrp,
			SignatureAlgorithm: r.SigAlg,
			AlertCount:         r.AlertCount,
			StreamID:           r.StreamID,
			ClientIP:           r.SrcIP,
			ClientPort:         srcPort,
			ServerIP:           r.DstIP,
			ServerPort:         dstPort,
			TLSObserved:        r.TLSObserved,
			ServerHelloSeen:    r.ServerHelloSeen,
			CertificateSeen:    r.CertificateSeen,
			HandshakeFailed:    r.AlertCount > 0 && !r.HandshakeCompleted && !r.AppDataObserved,
			HandshakeCompleted: r.HandshakeCompleted,
			AppDataObserved:    r.AppDataObserved,
			RawCertificates:    r.Certificates,
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
