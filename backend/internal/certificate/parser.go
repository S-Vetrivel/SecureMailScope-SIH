package certificate

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/securemailscope/backend/internal/models"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) ParseRawDER(derBytes []byte) (*models.CertificateInfo, error) {
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse X.509 certificate DER: %w", err)
	}

	return p.AnalyzeCertificate(cert), nil
}

func (p *Parser) ParsePEM(pemBytes []byte) (*models.CertificateInfo, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	return p.ParseRawDER(block.Bytes)
}

func (p *Parser) ParseHexStrings(hexCerts []string) (*models.CertificateInfo, error) {
	if len(hexCerts) == 0 {
		return nil, fmt.Errorf("no certificates provided")
	}

	// Just parse the first one (leaf cert) for now
	certHex := strings.ReplaceAll(hexCerts[0], ":", "")
	derBytes, err := hex.DecodeString(certHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex cert: %w", err)
	}
	
	return p.ParseRawDER(derBytes)
}

func (p *Parser) AnalyzeCertificate(cert *x509.Certificate) *models.CertificateInfo {
	now := time.Now()
	expired := now.After(cert.NotAfter)
	notYetValid := now.Before(cert.NotBefore)

	keyAlg, keyBits := extractPublicKeyDetails(cert.PublicKey)

	hash := sha256.Sum256(cert.Raw)
	fingerprint := hex.EncodeToString(hash[:])

	info := &models.CertificateInfo{
		Subject:            cert.Subject.String(),
		Issuer:             cert.Issuer.String(),
		SerialNumber:       cert.SerialNumber.String(),
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		KeyAlgorithm:       keyAlg,
		KeyBits:            keyBits,
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		DNSNames:           cert.DNSNames,
		Expired:            expired,
		NotYetValid:        notYetValid,
		ChainVerified:      nil, // Represent explicitly as UNKNOWN (null) unless full chain verified
		HostnameVerified:   nil,
		Fingerprint:        fingerprint,
	}

	return info
}

func extractPublicKeyDetails(pubKey interface{}) (string, int) {
	switch k := pubKey.(type) {
	case *rsa.PublicKey:
		return "RSA", k.N.BitLen()
	case *ecdsa.PublicKey:
		return "ECDSA", k.Curve.Params().BitSize
	default:
		return "Unknown", 0
	}
}
