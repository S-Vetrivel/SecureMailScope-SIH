package certificate

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
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

func (p *Parser) AnalyzeCertificate(cert *x509.Certificate) *models.CertificateInfo {
	now := time.Now()
	expired := now.After(cert.NotAfter)
	notYetValid := now.Before(cert.NotBefore)

	keyAlg, keyBits := extractPublicKeyDetails(cert.PublicKey)

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
