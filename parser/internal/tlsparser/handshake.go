// Package tlsparser provides TLS handshake parsing functionality.
// It extracts ClientHello, ServerHello, and Certificate messages from
// raw TLS record byte streams without decrypting any application data.
package tlsparser

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"github.com/securemailscope/parser/internal/models"
)

// TLS content types
const (
	ContentTypeChangeCipherSpec = 20
	ContentTypeAlert            = 21
	ContentTypeHandshake        = 22
	ContentTypeApplicationData  = 23
)

// TLS handshake types
const (
	HandshakeTypeClientHello   = 1
	HandshakeTypeServerHello   = 2
	HandshakeTypeCertificate   = 11
	HandshakeTypeServerKeyExch = 12
	HandshakeTypeServerDone    = 14
)

// TLS extension types
const (
	ExtServerName        = 0
	ExtSupportedVersions = 43
)

// CipherSuiteNames maps cipher suite hex codes to human-readable names.
var CipherSuiteNames = map[uint16]string{
	0x0000: "TLS_NULL_WITH_NULL_NULL",
	0x0001: "TLS_RSA_WITH_NULL_MD5",
	0x0002: "TLS_RSA_WITH_NULL_SHA",
	0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
	0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
	0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
	0x0039: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
	0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
	0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",
	0x0067: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
	0x006B: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
	0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
	0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
	0x009E: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
	0x009F: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
	0x00FF: "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
	0x1301: "TLS_AES_128_GCM_SHA256",
	0x1302: "TLS_AES_256_GCM_SHA384",
	0x1303: "TLS_CHACHA20_POLY1305_SHA256",
	0xC009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
	0xC00A: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
	0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
	0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
	0xC023: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
	0xC024: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
	0xC027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
	0xC028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
	0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
	0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
	0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
	0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
	0xCCAA: "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
	// Legacy/Weak ciphers
	0x0004: "TLS_RSA_WITH_RC4_128_MD5",
	0x0005: "TLS_RSA_WITH_RC4_128_SHA",
	0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
	0x0016: "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
	0xC003: "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
	0xC008: "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
	0xC012: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
	0x5600: "TLS_FALLBACK_SCSV",
}

// TLSVersionName returns a human-readable TLS version string.
func TLSVersionName(major, minor uint8) string {
	switch {
	case major == 3 && minor == 0:
		return "SSLv3"
	case major == 3 && minor == 1:
		return "TLS 1.0"
	case major == 3 && minor == 2:
		return "TLS 1.1"
	case major == 3 && minor == 3:
		return "TLS 1.2"
	case major == 3 && minor == 4:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown(%d.%d)", major, minor)
	}
}

// CipherSuiteName returns the name for a cipher suite code.
func CipherSuiteName(code uint16) string {
	if name, ok := CipherSuiteNames[code]; ok {
		return name
	}
	return fmt.Sprintf("Unknown(0x%04X)", code)
}

// HasForwardSecrecy checks if a cipher suite name indicates forward secrecy.
func HasForwardSecrecy(cipherName string) bool {
	if strings.Contains(cipherName, "ECDHE") || strings.Contains(cipherName, "DHE") {
		return true
	}
	if strings.HasPrefix(cipherName, "TLS_AES_") || strings.HasPrefix(cipherName, "TLS_CHACHA20_") {
		return true
	}
	return false
}

// KeyExchangeType extracts the key exchange mechanism from a cipher name.
func KeyExchangeType(cipherName string) string {
	switch {
	case strings.Contains(cipherName, "ECDHE"):
		return "ECDHE"
	case strings.Contains(cipherName, "DHE"):
		return "DHE"
	case strings.Contains(cipherName, "ECDH"):
		return "ECDH"
	case strings.Contains(cipherName, "RSA"):
		return "RSA"
	case strings.HasPrefix(cipherName, "TLS_AES_") || strings.HasPrefix(cipherName, "TLS_CHACHA20_"):
		return "ECDHE"
	default:
		return "Unknown"
	}
}

// ParseResult holds parsed TLS handshake data from a stream direction.
type ParseResult struct {
	Handshake    *models.TLSHandshake
	Certificates []models.CertInfo
	IsComplete   bool
}

// Parser processes raw TLS record bytes to extract handshake metadata.
type Parser struct {
	clientResult *ParseResult
	serverResult *ParseResult
}

// NewParser creates a new TLS parser instance.
func NewParser() *Parser {
	return &Parser{
		clientResult: &ParseResult{
			Handshake: &models.TLSHandshake{},
		},
		serverResult: &ParseResult{
			Handshake: &models.TLSHandshake{},
		},
	}
}

// ProcessRecord processes a single TLS record from the given direction.
// isServer indicates whether this record came from the server side.
func (p *Parser) ProcessRecord(data []byte, isServer bool) error {
	if len(data) < 5 {
		return fmt.Errorf("TLS record too short: %d bytes", len(data))
	}

	contentType := data[0]
	// recordVersion major/minor at data[1] and data[2]
	recordLen := binary.BigEndian.Uint16(data[3:5])

	if len(data) < int(5+recordLen) {
		return fmt.Errorf("TLS record truncated: expected %d, got %d", 5+recordLen, len(data))
	}

	payload := data[5 : 5+recordLen]

	if contentType == ContentTypeHandshake {
		return p.parseHandshake(payload, isServer)
	}

	return nil
}

// parseHandshake processes a TLS handshake message.
func (p *Parser) parseHandshake(data []byte, isServer bool) error {
	if len(data) < 4 {
		return fmt.Errorf("handshake message too short")
	}

	hsType := data[0]
	hsLen := int(data[1])<<16 | int(data[2])<<8 | int(data[3])

	if len(data) < 4+hsLen {
		hsLen = len(data) - 4
	}

	hsData := data[4 : 4+hsLen]

	switch hsType {
	case HandshakeTypeClientHello:
		return p.parseClientHello(hsData)
	case HandshakeTypeServerHello:
		return p.parseServerHello(hsData)
	case HandshakeTypeCertificate:
		return p.parseCertificateMessage(hsData)
	}

	return nil
}

// parseClientHello extracts metadata from a TLS ClientHello message.
func (p *Parser) parseClientHello(data []byte) error {
	if len(data) < 38 {
		return fmt.Errorf("ClientHello too short")
	}

	hs := p.clientResult.Handshake

	// Client version (2 bytes)
	major := data[0]
	minor := data[1]
	hs.ClientHelloVersion = TLSVersionName(major, minor)

	// Random (32 bytes) — skip
	// Session ID length + session ID
	offset := 34
	if offset >= len(data) {
		return nil
	}
	sessionIDLen := int(data[offset])
	offset += 1 + sessionIDLen

	// Cipher suites
	if offset+2 > len(data) {
		return nil
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	if offset+cipherSuitesLen > len(data) {
		cipherSuitesLen = len(data) - offset
	}

	cipherSuites := make([]string, 0)
	for i := 0; i+1 < cipherSuitesLen; i += 2 {
		code := binary.BigEndian.Uint16(data[offset+i : offset+i+2])
		cipherSuites = append(cipherSuites, CipherSuiteName(code))
	}
	hs.CipherSuitesOffered = cipherSuites
	offset += cipherSuitesLen

	// Compression methods
	if offset >= len(data) {
		return nil
	}
	compLen := int(data[offset])
	offset += 1 + compLen

	// Extensions
	if offset+2 > len(data) {
		return nil
	}
	extLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	extEnd := offset + extLen
	if extEnd > len(data) {
		extEnd = len(data)
	}

	for offset+4 <= extEnd {
		extType := binary.BigEndian.Uint16(data[offset : offset+2])
		extDataLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		offset += 4

		if offset+extDataLen > extEnd {
			break
		}

		extData := data[offset : offset+extDataLen]

		switch extType {
		case ExtServerName:
			p.parseSNIExtension(extData, hs)
		case ExtSupportedVersions:
			p.parseSupportedVersionsClient(extData, hs)
		}

		offset += extDataLen
	}

	return nil
}

// parseServerHello extracts metadata from a TLS ServerHello message.
func (p *Parser) parseServerHello(data []byte) error {
	if len(data) < 38 {
		return fmt.Errorf("ServerHello too short")
	}

	hs := p.serverResult.Handshake

	// Server version (2 bytes)
	major := data[0]
	minor := data[1]
	hs.ServerHelloVersion = TLSVersionName(major, minor)

	// Random (32 bytes) — skip
	// Session ID
	offset := 34
	if offset >= len(data) {
		return nil
	}
	sessionIDLen := int(data[offset])
	offset += 1 + sessionIDLen

	// Selected cipher suite (2 bytes)
	if offset+2 > len(data) {
		return nil
	}
	cipherCode := binary.BigEndian.Uint16(data[offset : offset+2])
	cipherName := CipherSuiteName(cipherCode)
	hs.NegotiatedCipher = cipherName
	hs.NegotiatedCipherHex = cipherCode
	hs.HasForwardSecrecy = HasForwardSecrecy(cipherName)
	hs.KeyExchange = KeyExchangeType(cipherName)
	offset += 2

	// Compression method (1 byte)
	if offset < len(data) {
		hs.CompressionMethod = data[offset]
		offset++
	}

	// Extensions
	if offset+2 > len(data) {
		hs.NegotiatedVersion = hs.ServerHelloVersion
		return nil
	}
	extLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	extEnd := offset + extLen
	if extEnd > len(data) {
		extEnd = len(data)
	}

	for offset+4 <= extEnd {
		extType := binary.BigEndian.Uint16(data[offset : offset+2])
		extDataLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		offset += 4

		if offset+extDataLen > extEnd {
			break
		}

		extData := data[offset : offset+extDataLen]

		if extType == ExtSupportedVersions && len(extData) >= 2 {
			selMajor := extData[0]
			selMinor := extData[1]
			hs.NegotiatedVersion = TLSVersionName(selMajor, selMinor)
		}

		offset += extDataLen
	}

	if hs.NegotiatedVersion == "" {
		hs.NegotiatedVersion = hs.ServerHelloVersion
	}

	p.serverResult.IsComplete = true
	return nil
}

// parseCertificateMessage extracts X.509 certificates from a TLS Certificate message.
func (p *Parser) parseCertificateMessage(data []byte) error {
	if len(data) < 3 {
		return fmt.Errorf("certificate message too short")
	}

	totalLen := int(data[0])<<16 | int(data[1])<<8 | int(data[2])
	offset := 3

	if totalLen > len(data)-3 {
		totalLen = len(data) - 3
	}

	certEnd := offset + totalLen

	for offset+3 <= certEnd {
		certLen := int(data[offset])<<16 | int(data[offset+1])<<8 | int(data[offset+2])
		offset += 3

		if offset+certLen > certEnd {
			break
		}

		certDER := data[offset : offset+certLen]
		offset += certLen

		certInfo := ParseDERCertificate(certDER)
		p.serverResult.Certificates = append(p.serverResult.Certificates, certInfo)
	}

	return nil
}

// parseSNIExtension extracts the Server Name Indication from extension data.
func (p *Parser) parseSNIExtension(data []byte, hs *models.TLSHandshake) {
	if len(data) < 5 {
		return
	}
	offset := 2
	if data[offset] != 0 {
		return
	}
	offset++
	nameLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2
	if offset+nameLen > len(data) {
		return
	}
	hs.SNI = string(data[offset : offset+nameLen])
}

// parseSupportedVersionsClient extracts supported TLS versions from ClientHello.
func (p *Parser) parseSupportedVersionsClient(data []byte, hs *models.TLSHandshake) {
	if len(data) < 1 {
		return
	}
	listLen := int(data[0])
	offset := 1
	for offset+1 < len(data) && offset < 1+listLen {
		major := data[offset]
		minor := data[offset+1]
		hs.SupportedVersions = append(hs.SupportedVersions, TLSVersionName(major, minor))
		offset += 2
	}
}

// GetResult returns the merged parse result combining client and server data.
func (p *Parser) GetResult() (*models.TLSHandshake, []models.CertInfo) {
	merged := &models.TLSHandshake{
		ClientHelloVersion:  p.clientResult.Handshake.ClientHelloVersion,
		ServerHelloVersion:  p.serverResult.Handshake.ServerHelloVersion,
		NegotiatedVersion:   p.serverResult.Handshake.NegotiatedVersion,
		NegotiatedCipher:    p.serverResult.Handshake.NegotiatedCipher,
		NegotiatedCipherHex: p.serverResult.Handshake.NegotiatedCipherHex,
		CipherSuitesOffered: p.clientResult.Handshake.CipherSuitesOffered,
		SNI:                 p.clientResult.Handshake.SNI,
		HasForwardSecrecy:   p.serverResult.Handshake.HasForwardSecrecy,
		KeyExchange:         p.serverResult.Handshake.KeyExchange,
		CompressionMethod:   p.serverResult.Handshake.CompressionMethod,
		SupportedVersions:   p.clientResult.Handshake.SupportedVersions,
	}

	if merged.NegotiatedVersion == "" && merged.ServerHelloVersion != "" {
		merged.NegotiatedVersion = merged.ServerHelloVersion
	}

	return merged, p.serverResult.Certificates
}

// ParseDERCertificate parses a DER-encoded X.509 certificate into CertInfo.
func ParseDERCertificate(der []byte) models.CertInfo {
	info := models.CertInfo{}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		info.Subject = fmt.Sprintf("Parse error: %v", err)
		return info
	}

	info.Subject = cert.Subject.String()
	info.Issuer = cert.Issuer.String()
	info.SerialNumber = cert.SerialNumber.String()
	info.NotBefore = cert.NotBefore
	info.NotAfter = cert.NotAfter
	info.SignatureAlgorithm = cert.SignatureAlgorithm.String()
	info.Version = cert.Version
	info.DNSNames = cert.DNSNames
	info.IsSelfSigned = cert.Subject.String() == cert.Issuer.String()
	info.IsExpired = cert.NotAfter.Before(time.Now())

	// Public key analysis
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		info.PublicKeyAlgorithm = "RSA"
		info.PublicKeyBitLength = pub.N.BitLen()
		info.IsWeakKey = info.PublicKeyBitLength < 2048
	default:
		info.PublicKeyAlgorithm = cert.PublicKeyAlgorithm.String()
		// For ECDSA, Ed25519, etc., keys are generally not weak
		info.IsWeakKey = false
	}

	// Weak signature detection
	weakSigAlgos := map[x509.SignatureAlgorithm]bool{
		x509.MD2WithRSA:    true,
		x509.MD5WithRSA:    true,
		x509.SHA1WithRSA:   true,
		x509.ECDSAWithSHA1: true,
	}
	info.IsWeakSignature = weakSigAlgos[cert.SignatureAlgorithm]

	return info
}
