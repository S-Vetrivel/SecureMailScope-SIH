package protocol

import (
	"strings"

	"github.com/securemailscope/backend/internal/models"
)

type ProtocolDetection struct {
	Protocol   models.EmailProtocol `json:"protocol"`
	Confidence float64              `json:"confidence"`
	Evidence   []string             `json:"evidence"`
}

type Detector struct{}

func NewDetector() *Detector {
	return &Detector{}
}

func (d *Detector) Detect(srcPort, dstPort uint16, payload []byte) ProtocolDetection {
	var evidence []string
	var smtpScore, imapScore, pop3Score float64

	// 1. Port heuristics — standard AND common alternate ports
	if isSMTPPort(dstPort) || isSMTPPort(srcPort) {
		smtpScore += 0.5
		evidence = append(evidence, "SMTP port match")
	}
	if isIMAPPort(dstPort) || isIMAPPort(srcPort) {
		imapScore += 0.5
		evidence = append(evidence, "IMAP port match")
	}
	if isPOP3Port(dstPort) || isPOP3Port(srcPort) {
		pop3Score += 0.5
		evidence = append(evidence, "POP3 port match")
	}

	// 2. Application layer evidence — inspect combined payload
	if len(payload) > 0 {
		payloadStr := strings.ToUpper(string(payload))

		// SMTP indicators
		smtpSignals := 0
		if strings.Contains(payloadStr, "220 ") || strings.Contains(payloadStr, "220-") {
			smtpSignals++
		}
		if strings.Contains(payloadStr, "EHLO") || strings.Contains(payloadStr, "HELO") {
			smtpSignals++
		}
		if strings.Contains(payloadStr, "MAIL FROM") || strings.Contains(payloadStr, "RCPT TO") {
			smtpSignals++
		}
		if strings.Contains(payloadStr, "250 ") || strings.Contains(payloadStr, "250-") {
			smtpSignals++
		}
		if strings.Contains(payloadStr, "STARTTLS") && !strings.Contains(payloadStr, "STLS") {
			smtpSignals++
		}
		if smtpSignals > 0 {
			smtpScore += float64(smtpSignals) * 0.2
			evidence = append(evidence, "SMTP application signatures detected")
		}

		// IMAP indicators
		imapSignals := 0
		if strings.Contains(payloadStr, "* OK") {
			imapSignals++
		}
		if strings.Contains(payloadStr, "CAPABILITY") {
			imapSignals++
		}
		if strings.Contains(payloadStr, "IMAP") {
			imapSignals++
		}
		if strings.Contains(payloadStr, "LOGIN") || strings.Contains(payloadStr, "AUTHENTICATE") {
			imapSignals++
		}
		if strings.Contains(payloadStr, "A001") || strings.Contains(payloadStr, "A002") {
			imapSignals++ // IMAP tagged commands
		}
		if imapSignals > 0 {
			imapScore += float64(imapSignals) * 0.2
			evidence = append(evidence, "IMAP application signatures detected")
		}

		// POP3 indicators
		pop3Signals := 0
		if strings.Contains(payloadStr, "+OK") {
			pop3Signals++
		}
		if strings.Contains(payloadStr, "-ERR") {
			pop3Signals++
		}
		if strings.Contains(payloadStr, "USER ") || strings.Contains(payloadStr, "PASS ") {
			pop3Signals++
		}
		if strings.Contains(payloadStr, "STLS") {
			pop3Signals++
		}
		if strings.Contains(payloadStr, "RETR") || strings.Contains(payloadStr, "LIST") {
			pop3Signals++
		}
		if pop3Signals > 0 {
			pop3Score += float64(pop3Signals) * 0.2
			evidence = append(evidence, "POP3 application signatures detected")
		}
	}

	// Select highest confidence protocol
	if smtpScore > 0 && smtpScore >= imapScore && smtpScore >= pop3Score {
		conf := smtpScore
		if conf > 1.0 {
			conf = 1.0
		}
		return ProtocolDetection{Protocol: models.ProtocolSMTP, Confidence: conf, Evidence: evidence}
	}
	if imapScore > 0 && imapScore >= pop3Score {
		conf := imapScore
		if conf > 1.0 {
			conf = 1.0
		}
		return ProtocolDetection{Protocol: models.ProtocolIMAP, Confidence: conf, Evidence: evidence}
	}
	if pop3Score > 0 {
		conf := pop3Score
		if conf > 1.0 {
			conf = 1.0
		}
		return ProtocolDetection{Protocol: models.ProtocolPOP3, Confidence: conf, Evidence: evidence}
	}

	return ProtocolDetection{
		Protocol:   models.ProtocolUnknown,
		Confidence: 0.0,
		Evidence:   []string{"no matching email protocol signatures"},
	}
}

// Standard + common alternate/test SMTP ports
func isSMTPPort(port uint16) bool {
	switch port {
	case 25, 465, 587, 2525, 10025, 10466, 10465, 10587:
		return true
	}
	return false
}

// Standard + alternate IMAP ports
func isIMAPPort(port uint16) bool {
	switch port {
	case 143, 993, 10143, 10993:
		return true
	}
	return false
}

// Standard + alternate POP3 ports
func isPOP3Port(port uint16) bool {
	switch port {
	case 110, 995, 10110, 10995:
		return true
	}
	return false
}
