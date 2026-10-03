package risk

import (
	"fmt"
	"strings"

	"github.com/securemailscope/backend/internal/models"
)

type Policy struct {
	AllowedTLSVersions        []string `yaml:"allowed_tls_versions"`
	MinimumRSABits            int      `yaml:"minimum_rsa_bits"`
	MinimumECDSABits          int      `yaml:"minimum_ecdsa_bits"`
	RequireForwardSecrecy     bool     `yaml:"require_forward_secrecy"`
	RejectExpiredCertificates bool     `yaml:"reject_expired_certificates"`
}

func DefaultPolicy() Policy {
	return Policy{
		AllowedTLSVersions:        []string{"TLS 1.2", "TLS 1.3"},
		MinimumRSABits:            2048,
		MinimumECDSABits:          256,
		RequireForwardSecrecy:     true,
		RejectExpiredCertificates: true,
	}
}

type Engine struct {
	Policy Policy
}

func NewEngine(policy Policy) *Engine {
	return &Engine{Policy: policy}
}

func (e *Engine) Assess(session models.EmailSession) []models.Finding {
	var findings []models.Finding

	// STARTTLS Rules
	if session.StartTLS.Supported && !session.StartTLS.Requested {
		findings = append(findings, models.Finding{
			ID:          fmt.Sprintf("STARTTLS-001-%s", session.ID),
			Title:       "STARTTLS Supported But Not Requested",
			Severity:    models.SeverityHigh,
			Category:    "STARTTLS",
			SessionID:   session.ID,
			Description: "The email server advertised STARTTLS encryption capability, but the client failed to send the STARTTLS upgrade command.",
			Confidence:  "HIGH",
			Evidence:    models.FindingEvidence{SessionID: session.ID, PCAP: "capture.pcap", Details: "Server EHLO response included 250-STARTTLS, No STARTTLS command in client stream"},
			Recommendation: "Configure the email client to enforce mandatory STARTTLS encryption (Opportunistic or Strict TLS).",
		})
	}

	if session.StartTLS.Requested && !session.StartTLS.Accepted {
		findings = append(findings, models.Finding{
			ID:          fmt.Sprintf("STARTTLS-002-%s", session.ID),
			Title:       "STARTTLS Upgrade Request Rejected",
			Severity:    models.SeverityCritical,
			Category:    "STARTTLS",
			SessionID:   session.ID,
			Description: "The email client requested STARTTLS upgrade, but the server rejected or returned an error response.",
			Confidence:  "HIGH",
			Evidence:    models.FindingEvidence{SessionID: session.ID, PCAP: "capture.pcap", Details: fmt.Sprintf("STARTTLS response code: %s", session.StartTLS.ResponseCode)},
			Recommendation: "Inspect server STARTTLS configuration and TLS certificate setup on port 587/143/110.",
		})
	}

	if session.StartTLS.State == models.StateStartTLSNotUsed && len(session.ProtocolEvents) > 0 {
		// Found plaintext protocol interactions
		hasAuth := false
		for _, e := range session.ProtocolEvents {
			cmd := strings.ToUpper(e.Command)
			if strings.HasPrefix(cmd, "AUTH") || strings.HasPrefix(cmd, "LOGIN") || strings.HasPrefix(cmd, "PASS") {
				hasAuth = true
				break
			}
		}
		
		title := "Plaintext Session"
		sev := models.SeverityHigh
		if hasAuth {
			title = "Plaintext Authentication Detected"
			sev = models.SeverityCritical
		}

		findings = append(findings, models.Finding{
			ID:          fmt.Sprintf("PLAINTEXT-001-%s", session.ID),
			Title:       title,
			Severity:    sev,
			Category:    "PROTOCOL",
			SessionID:   session.ID,
			Description: "The session communicated in plaintext without upgrading to TLS.",
			Confidence:  "HIGH",
			Evidence:    models.FindingEvidence{SessionID: session.ID, PCAP: "capture.pcap", Details: "STARTTLS not negotiated successfully before commands"},
			Recommendation: "Enforce TLS for all mail sessions, especially those sending authentication credentials.",
		})
	}

	// TLS Handshake Rules
	if session.TLS != nil {
		// Version checks
		isVersionAllowed := false
		for _, v := range e.Policy.AllowedTLSVersions {
			if session.TLS.Version == v {
				isVersionAllowed = true
				break
			}
		}

		if !isVersionAllowed && session.TLS.Version != "" {
			severity := models.SeverityHigh
			if session.TLS.Version == "TLS 1.0" || session.TLS.Version == "TLS 1.1" {
				severity = models.SeverityCritical
			}
			findings = append(findings, models.Finding{
				ID:          fmt.Sprintf("TLS-001-%s", session.ID),
				Title:       "Deprecated or Non-Compliant TLS Version",
				Severity:    severity,
				Category:    "TLS",
				SessionID:   session.ID,
				Description: fmt.Sprintf("The connection negotiated %s, which is deprecated under security policy.", session.TLS.Version),
				Confidence:  "HIGH",
				Evidence:    models.FindingEvidence{SessionID: session.ID, PCAP: "capture.pcap", Details: fmt.Sprintf("Negotiated TLS Version: %s", session.TLS.Version)},
				Recommendation: "Disable TLS 1.0 and TLS 1.1 on the mail server. Require TLS 1.2 or TLS 1.3.",
			})
		}

		// Weak Ciphers / Non-AEAD
		if session.TLS.CipherSuite != "" && session.TLS.CipherSuite != "UNKNOWN" {
			cinfo := ClassifyCipher(session.TLS.CipherSuite)
			
			hasSufficientEvidence := session.TLS.HandshakeCompleted || session.TLS.CertificateSeen || session.TLS.AppDataObserved

			if hasSufficientEvidence && cinfo.Type != CipherUnknown {
				if cinfo.IsWeak {
					findings = append(findings, models.Finding{
						ID:          fmt.Sprintf("CIPHER-001-%s", session.ID),
						Title:       "Obsolete/Weak Cipher Suite Negotiated",
						Severity:    models.SeverityCritical,
						Category:    "CIPHER",
						SessionID:   session.ID,
						Description: fmt.Sprintf("The negotiated cipher suite %s relies on broken or vulnerable cryptographic primitives.", session.TLS.CipherSuite),
						Confidence:  "HIGH",
						Evidence:    models.FindingEvidence{SessionID: session.ID, PCAP: "capture.pcap", Details: fmt.Sprintf("Cipher Suite: %s", session.TLS.CipherSuite)},
						Recommendation: "Reconfigure cipher suites to include only AES-GCM, CHACHA20-POLY1305, and modern AEAD ciphers.",
					})
				} else if !cinfo.IsAEAD {
					findings = append(findings, models.Finding{
						ID:          fmt.Sprintf("CIPHER-002-%s", session.ID),
						Title:       "Non-AEAD Cipher Negotiated",
						Severity:    models.SeverityMedium,
						Category:    "CIPHER",
						SessionID:   session.ID,
						Description: fmt.Sprintf("The cipher %s is not an Authenticated Encryption with Associated Data (AEAD) cipher, which is less robust against tampering.", session.TLS.CipherSuite),
						Confidence:  "HIGH",
						Evidence:    models.FindingEvidence{SessionID: session.ID, PCAP: "capture.pcap", Details: fmt.Sprintf("Cipher Suite: %s is type %s", session.TLS.CipherSuite, cinfo.Type)},
						Recommendation: "Prioritize AEAD ciphers like GCM or CHACHA20-POLY1305.",
					})
				}

				// Forward Secrecy Check via Cipher
				if e.Policy.RequireForwardSecrecy && !cinfo.IsPFS {
					findings = append(findings, models.Finding{
						ID:          fmt.Sprintf("FS-001-%s", session.ID),
						Title:       "Lack of Perfect Forward Secrecy (PFS)",
						Severity:    models.SeverityMedium,
						Category:    "KEY_EXCHANGE",
						SessionID:   session.ID,
						Description: "The negotiated session cipher does not support Perfect Forward Secrecy, exposing past recorded traffic to decryption if long-term RSA keys are compromised.",
						Confidence:  "HIGH",
						Evidence:    models.FindingEvidence{SessionID: session.ID, PCAP: "capture.pcap", Details: fmt.Sprintf("Cipher: %s, Key Exchange: %s", session.TLS.CipherSuite, cinfo.KeyExchangeAlg)},
						Recommendation: "Configure server key exchange algorithms to prioritize ECDHE or DHE key exchange.",
					})
				}
			}
		}

		// TLS Handshake Failure / Alerts
		if session.TLS.AlertCount > 0 || session.TLS.HandshakeFailed {
			findings = append(findings, models.Finding{
				ID:          fmt.Sprintf("TLS-FAIL-001-%s", session.ID),
				Title:       "TLS Handshake Failure / Alert",
				Severity:    models.SeverityHigh,
				Category:    "TLS",
				SessionID:   session.ID,
				Description: "The TLS handshake failed or generated alert messages.",
				Confidence:  "HIGH",
				Evidence:    models.FindingEvidence{SessionID: session.ID, PCAP: "capture.pcap", Details: fmt.Sprintf("Alert Count: %d, Handshake Failed: %t", session.TLS.AlertCount, session.TLS.HandshakeFailed)},
				Recommendation: "Investigate TLS connectivity issues, possible certificate trust errors on client, or incompatible ciphers.",
			})
		}
	}

	// Certificate Rules
	if session.Certificate != nil {
		if session.Certificate.Expired {
			findings = append(findings, models.Finding{
				ID:          fmt.Sprintf("CERT-001-%s", session.ID),
				Title:       "Expired X.509 Certificate",
				Severity:    models.SeverityHigh,
				Category:    "CERTIFICATE",
				SessionID:   session.ID,
				Description: fmt.Sprintf("The server presented an X.509 certificate that expired on %s.", session.Certificate.NotAfter.Format("2006-01-02")),
				Confidence:  "HIGH",
				Evidence:    models.FindingEvidence{SessionID: session.ID, PCAP: "capture.pcap", Details: fmt.Sprintf("NotAfter: %s, Subject: %s", session.Certificate.NotAfter, session.Certificate.Subject)},
				Recommendation: "Renew and deploy a valid, non-expired X.509 TLS certificate.",
			})
		}

		if session.Certificate.NotYetValid {
			findings = append(findings, models.Finding{
				ID:          fmt.Sprintf("CERT-002-%s", session.ID),
				Title:       "Certificate Not Yet Valid",
				Severity:    models.SeverityHigh,
				Category:    "CERTIFICATE",
				SessionID:   session.ID,
				Description: fmt.Sprintf("The server presented an X.509 certificate whose validity start date (%s) is in the future.", session.Certificate.NotBefore.Format("2006-01-02")),
				Confidence:  "HIGH",
				Evidence:    models.FindingEvidence{SessionID: session.ID, PCAP: "capture.pcap", Details: fmt.Sprintf("NotBefore: %s", session.Certificate.NotBefore)},
				Recommendation: "Ensure system clocks are synchronized via NTP and check certificate validity issuance period.",
			})
		}

		if session.Certificate.KeyAlgorithm == "RSA" && session.Certificate.KeyBits < e.Policy.MinimumRSABits && session.Certificate.KeyBits > 0 {
			findings = append(findings, models.Finding{
				ID:          fmt.Sprintf("KEY-001-%s", session.ID),
				Title:       "Weak RSA Key Size",
				Severity:    models.SeverityHigh,
				Category:    "CERTIFICATE",
				SessionID:   session.ID,
				Description: fmt.Sprintf("The certificate public key is an RSA %d-bit key, below the required minimum of %d bits.", session.Certificate.KeyBits, e.Policy.MinimumRSABits),
				Confidence:  "HIGH",
				Evidence:    models.FindingEvidence{SessionID: session.ID, PCAP: "capture.pcap", Details: fmt.Sprintf("Public Key: RSA %d bits", session.Certificate.KeyBits)},
				Recommendation: "Re-issue certificate with an RSA key size of at least 2048 bits or switch to ECDSA (P-256/P-384).",
			})
		}

		sigAlgUpper := strings.ToUpper(session.Certificate.SignatureAlgorithm)
		if strings.Contains(sigAlgUpper, "MD5") || strings.Contains(sigAlgUpper, "SHA1") {
			findings = append(findings, models.Finding{
				ID:          fmt.Sprintf("SIG-001-%s", session.ID),
				Title:       "Weak Certificate Signature Algorithm",
				Severity:    models.SeverityCritical,
				Category:    "CERTIFICATE",
				SessionID:   session.ID,
				Description: fmt.Sprintf("The certificate uses a weak signature algorithm (%s) susceptible to collision attacks.", session.Certificate.SignatureAlgorithm),
				Confidence:  "HIGH",
				Evidence:    models.FindingEvidence{SessionID: session.ID, PCAP: "capture.pcap", Details: fmt.Sprintf("Signature Algorithm: %s", session.Certificate.SignatureAlgorithm)},
				Recommendation: "Re-issue certificate using SHA-256 or stronger.",
			})
		}
	}

	return findings
}
