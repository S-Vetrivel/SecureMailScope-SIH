package protocol

import (
	"strings"

	"github.com/securemailscope/backend/internal/models"
)

type StartTLSAnalyzer struct{}

func NewStartTLSAnalyzer() *StartTLSAnalyzer {
	return &StartTLSAnalyzer{}
}

func (a *StartTLSAnalyzer) Analyze(proto models.EmailProtocol, clientPayload, serverPayload []byte) models.StartTLSInfo {
	info := models.StartTLSInfo{
		Supported:      false,
		Requested:      false,
		Accepted:       false,
		TLSStarted:     false,
		TLSEstablished: false,
	}

	clientStr := strings.ToUpper(string(clientPayload))
	serverStr := strings.ToUpper(string(serverPayload))

	switch proto {
	case models.ProtocolSMTP:
		// Check banner / EHLO response for STARTTLS capability
		if strings.Contains(serverStr, "250-STARTTLS") || strings.Contains(serverStr, "250 STARTTLS") {
			info.Supported = true
		}
		if strings.Contains(clientStr, "STARTTLS") {
			info.Requested = true
		}
		if info.Requested && (strings.Contains(serverStr, "220 ") || strings.Contains(serverStr, "220 GO AHEAD") || strings.Contains(serverStr, "2.0.0 READY")) {
			info.Accepted = true
			info.TLSStarted = true
			info.ResponseCode = "220"
		}

	case models.ProtocolIMAP:
		if strings.Contains(serverStr, "STARTTLS") || strings.Contains(serverStr, "CAPABILITY") {
			info.Supported = true
		}
		if strings.Contains(clientStr, "STARTTLS") {
			info.Requested = true
		}
		if info.Requested && (strings.Contains(serverStr, "OK BEGIN TLS") || strings.Contains(serverStr, "OK STARTTLS")) {
			info.Accepted = true
			info.TLSStarted = true
			info.ResponseCode = "OK"
		}

	case models.ProtocolPOP3:
		if strings.Contains(serverStr, "STLS") || strings.Contains(serverStr, "+OK") {
			info.Supported = true
		}
		if strings.Contains(clientStr, "STLS") {
			info.Requested = true
		}
		if info.Requested && strings.Contains(serverStr, "+OK BEGIN TLS") {
			info.Accepted = true
			info.TLSStarted = true
			info.ResponseCode = "+OK"
		}
	}

	// Detect TLS ClientHello magic bytes (0x16 0x03) in client stream following STARTTLS
	if bytesContainTLSClientHello(clientPayload) {
		info.TLSEstablished = true
	}

	return info
}

func bytesContainTLSClientHello(payload []byte) bool {
	for i := 0; i < len(payload)-5; i++ {
		if payload[i] == 0x16 && payload[i+1] == 0x03 && (payload[i+2] >= 0x00 && payload[i+2] <= 0x04) {
			if payload[i+5] == 0x01 { // Handshake type: ClientHello
				return true
			}
		}
	}
	return false
}
