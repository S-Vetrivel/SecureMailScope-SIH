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
			Evidence:    []string{"Server EHLO response included 250-STARTTLS", "No STARTTLS command in client stream"},
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
			Evidence:    []string{fmt.Sprintf("STARTTLS response code: %s", session.StartTLS.ResponseCode)},
			Recommendation: "Inspect server STARTTLS configuration and TLS certificate setup on port 587/143/110.",
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
				Evidence:    []string{fmt.Sprintf("Negotiated TLS Version: %s", session.TLS.Version)},
				Recommendation: "Disable TLS 1.0 and TLS 1.1 on the mail server. Require TLS 1.2 or TLS 1.3.",
			})
		}

		// Weak Ciphers
		if strings.Contains(session.TLS.CipherSuite, "RC4") || strings.Contains(session.TLS.CipherSuite, "3DES") || strings.Contains(session.TLS.CipherSuite, "DES") {
			findings = append(findings, models.Finding{
				ID:          fmt.Sprintf("CIPHER-001-%s", session.ID),
				Title:       "Obsolete/Weak Cipher Suite Negotiated",
				Severity:    models.SeverityCritical,
				Category:    "CIPHER",
				SessionID:   session.ID,
				Description: fmt.Sprintf("The negotiated cipher suite %s relies on broken or vulnerable cryptographic primitives.", session.TLS.CipherSuite),
				Evidence:    []string{fmt.Sprintf("Cipher Suite: %s", session.TLS.CipherSuite)},
				Recommendation: "Reconfigure cipher suites to include only AES-GCM, CHACHA20-POLY1305, and modern AEAD ciphers.",
			})
		}

		// Forward Secrecy Check
		if e.Policy.RequireForwardSecrecy && session.ForwardSecrecy == models.FSNo {
			findings = append(findings, models.Finding{
				ID:          fmt.Sprintf("FS-001-%s", session.ID),
				Title:       "Lack of Perfect Forward Secrecy (PFS)",
				Severity:    models.SeverityMedium,
				Category:    "KEY_EXCHANGE",
				SessionID:   session.ID,
				Description: "The negotiated session cipher does not support Perfect Forward Secrecy, exposing past recorded traffic to decryption if long-term RSA keys are compromised.",
				Evidence:    []string{fmt.Sprintf("Cipher: %s", session.TLS.CipherSuite), "Forward Secrecy: NO"},
				Recommendation: "Configure server key exchange algorithms to prioritize ECDHE or DHE key exchange.",
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
				Evidence:    []string{fmt.Sprintf("NotAfter: %s", session.Certificate.NotAfter), fmt.Sprintf("Subject: %s", session.Certificate.Subject)},
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
				Evidence:    []string{fmt.Sprintf("NotBefore: %s", session.Certificate.NotBefore)},
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
				Evidence:    []string{fmt.Sprintf("Public Key: RSA %d bits", session.Certificate.KeyBits)},
				Recommendation: "Re-issue certificate with an RSA key size of at least 2048 bits or switch to ECDSA (P-256/P-384).",
			})
		}
	}

	return findings
}
