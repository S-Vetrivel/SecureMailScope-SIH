// Package models defines the data structures for parsed email session metadata.
// These structures are serialized to JSON and consumed by the Python AI engine.
package models

import "time"

// EmailSession represents a single reconstructed email communication session
// extracted from PCAP traffic, including TLS handshake and certificate details.
type EmailSession struct {
	SessionID    string        `json:"session_id"`
	SrcIP        string        `json:"src_ip"`
	SrcPort      uint16        `json:"src_port"`
	DstIP        string        `json:"dst_ip"`
	DstPort      uint16        `json:"dst_port"`
	Protocol     string        `json:"protocol"`      // SMTP, IMAP, POP3
	ProtocolPort uint16        `json:"protocol_port"`  // Original well-known port
	StartTime    time.Time     `json:"start_time"`
	EndTime      time.Time     `json:"end_time"`
	HasSTARTTLS  bool          `json:"has_starttls"`
	IsEncrypted  bool          `json:"is_encrypted"`
	TLSHandshake *TLSHandshake `json:"tls_handshake,omitempty"`
	Certificates []CertInfo    `json:"certificates,omitempty"`
	RawBanner    string        `json:"raw_banner,omitempty"` // First bytes of plaintext for protocol detection
}

// TLSHandshake captures the negotiated parameters from TLS ClientHello/ServerHello.
type TLSHandshake struct {
	ClientHelloVersion  string   `json:"client_hello_version"`
	ServerHelloVersion  string   `json:"server_hello_version"`
	NegotiatedVersion   string   `json:"negotiated_version"`
	NegotiatedCipher    string   `json:"negotiated_cipher"`
	NegotiatedCipherHex uint16   `json:"negotiated_cipher_hex"`
	CipherSuitesOffered []string `json:"cipher_suites_offered"`
	SNI                 string   `json:"sni,omitempty"`
	HasForwardSecrecy   bool     `json:"has_forward_secrecy"`
	KeyExchange         string   `json:"key_exchange"`
	CompressionMethod   uint8    `json:"compression_method"`
	SupportedVersions   []string `json:"supported_versions,omitempty"`
}

// CertInfo holds parsed X.509 certificate metadata for security analysis.
type CertInfo struct {
	Subject            string    `json:"subject"`
	Issuer             string    `json:"issuer"`
	SerialNumber       string    `json:"serial_number"`
	NotBefore          time.Time `json:"not_before"`
	NotAfter           time.Time `json:"not_after"`
	PublicKeyAlgorithm string    `json:"public_key_algorithm"`
	PublicKeyBitLength int       `json:"public_key_bit_length"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
	IsSelfSigned       bool      `json:"is_self_signed"`
	IsExpired          bool      `json:"is_expired"`
	IsWeakKey          bool      `json:"is_weak_key"`
	IsWeakSignature    bool      `json:"is_weak_signature"`
	DNSNames           []string  `json:"dns_names,omitempty"`
	Version            int       `json:"version"`
}

// AnalysisOutput is the top-level JSON output from the parser.
type AnalysisOutput struct {
	AnalysisID   string          `json:"analysis_id"`
	PcapFile     string          `json:"pcap_file"`
	ParsedAt     time.Time       `json:"parsed_at"`
	TotalPackets int             `json:"total_packets"`
	TotalStreams  int             `json:"total_streams"`
	Sessions     []*EmailSession `json:"sessions"`
}
