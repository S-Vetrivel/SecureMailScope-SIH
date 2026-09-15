package models

import (
	"time"
)

type AnalysisStatus string

const (
	StatusQueued              AnalysisStatus = "QUEUED"
	StatusParsing             AnalysisStatus = "PARSING"
	StatusReassembling        AnalysisStatus = "REASSEMBLING"
	StatusDetectingProtocols  AnalysisStatus = "DETECTING_PROTOCOLS"
	StatusAnalyzingStartTLS   AnalysisStatus = "ANALYZING_STARTTLS"
	StatusAnalyzingTLS        AnalysisStatus = "ANALYZING_TLS"
	StatusAnalyzingCerts      AnalysisStatus = "ANALYZING_CERTIFICATES"
	StatusAssessingRisk       AnalysisStatus = "ASSESSING_RISK"
	StatusCompleted           AnalysisStatus = "COMPLETED"
	StatusFailed              AnalysisStatus = "FAILED"
)

type EmailProtocol string

const (
	ProtocolSMTP    EmailProtocol = "SMTP"
	ProtocolIMAP    EmailProtocol = "IMAP"
	ProtocolPOP3    EmailProtocol = "POP3"
	ProtocolUnknown EmailProtocol = "UNKNOWN"
)

type ForwardSecrecyStatus string

const (
	FSYes     ForwardSecrecyStatus = "YES"
	FSNo      ForwardSecrecyStatus = "NO"
	FSUnknown ForwardSecrecyStatus = "UNKNOWN"
)

type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

type Analysis struct {
	ID                string            `json:"id"`
	PCAPPath          string            `json:"pcap_path"`
	PCAPFilename      string            `json:"pcap_filename"`
	Status            AnalysisStatus    `json:"status"`
	StartedAt         time.Time         `json:"started_at"`
	FinishedAt        *time.Time        `json:"finished_at,omitempty"`
	TotalPackets      int               `json:"total_packets"`
	TotalSessions     int               `json:"total_sessions"`
	OverallScore      float64           `json:"overall_score"`
	OverallSeverity   string            `json:"overall_severity"`
	ForwardSecrecyPct float64           `json:"forward_secrecy_pct"`
	AnomalyCount      int               `json:"anomaly_count"`
	SeverityBreakdown map[string]int    `json:"severity_breakdown"`
	Error             string            `json:"error,omitempty"`
}

type StartTLSInfo struct {
	Supported      bool   `json:"supported"`
	Requested      bool   `json:"requested"`
	Accepted       bool   `json:"accepted"`
	TLSStarted     bool   `json:"tls_started"`
	TLSEstablished bool   `json:"tls_established"`
	ResponseCode   string `json:"response_code,omitempty"`
}

type TLSInfo struct {
	Version            string `json:"version"`
	CipherSuite        string `json:"cipher_suite"`
	ServerName         string `json:"server_name,omitempty"`
	SignatureAlgorithm string `json:"signature_algorithm,omitempty"`
	HandshakeSucceeded bool   `json:"handshake_succeeded"`
	CertificateSeen    bool   `json:"certificate_seen"`
	AlertCount         int    `json:"alert_count"`
	StreamID           int    `json:"stream_id"`
	Complete           bool   `json:"complete"`
}

type CertificateInfo struct {
	Subject            string    `json:"subject"`
	Issuer             string    `json:"issuer"`
	SerialNumber       string    `json:"serial_number"`
	NotBefore          time.Time `json:"not_before"`
	NotAfter           time.Time `json:"not_after"`
	KeyAlgorithm       string    `json:"key_algorithm"`
	KeyBits            int       `json:"key_bits"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
	DNSNames           []string  `json:"dns_names"`
	Expired            bool      `json:"expired"`
	NotYetValid        bool      `json:"not_yet_valid"`
	ChainVerified      *bool     `json:"chain_verified"`
	HostnameVerified   *bool     `json:"hostname_verified"`
	ParseError         string    `json:"parse_error,omitempty"`
}

type Finding struct {
	ID             string   `json:"id"`
	Title          string   `json:"title"`
	Severity       Severity `json:"severity"`
	Category       string   `json:"category"`
	SessionID      string   `json:"session_id"`
	Description    string   `json:"description"`
	Evidence       []string `json:"evidence"`
	Recommendation string   `json:"recommendation"`
}

type Endpoint struct {
	IP   string `json:"ip"`
	Port uint16 `json:"port"`
}

type EmailSession struct {
	// Canonical fields
	ID             string               `json:"id"`
	AnalysisID     string               `json:"analysis_id"`
	Client         Endpoint             `json:"client"`
	Server         Endpoint             `json:"server"`
	Protocol       EmailProtocol        `json:"protocol"`
	StartTime      time.Time            `json:"start_time"`
	EndTime        time.Time            `json:"end_time"`
	PacketCount    int                  `json:"packet_count"`
	ClientBytes    int64                `json:"client_bytes"`
	ServerBytes    int64                `json:"server_bytes"`
	StreamComplete bool                 `json:"stream_complete"`
	ReassemblyGap  bool                 `json:"reassembly_gap"`
	StartTLS       StartTLSInfo         `json:"starttls"`
	TLS            *TLSInfo             `json:"tls,omitempty"`
	Certificate    *CertificateInfo     `json:"certificate,omitempty"`
	ForwardSecrecy ForwardSecrecyStatus `json:"forward_secrecy"`
	Findings       []Finding            `json:"findings"`

	// Dashboard-friendly flat aliases (computed at response time)
	SessionID          string  `json:"session_id"`
	SrcIP              string  `json:"src_ip"`
	DstIP              string  `json:"dst_ip"`
	TLSVersion         string  `json:"tls_version"`
	NegotiatedCipher   string  `json:"negotiated_cipher"`
	SignatureAlgorithm string  `json:"signature_algorithm"`
	RiskScore          float64 `json:"risk_score"`
	Severity           string  `json:"severity"`
	HasForwardSecrecy  bool    `json:"has_forward_secrecy"`
	IsAnomalous        bool    `json:"is_anomalous"`
	AnomalyScore       float64 `json:"anomaly_score"`
	Scores             SessionScores `json:"scores"`
}

// SessionScores drives the Security Radar chart
type SessionScores struct {
	TLSVersion         float64 `json:"tls_version"`
	CipherStrength     float64 `json:"cipher_strength"`
	KeyExchange        float64 `json:"key_exchange"`
	Certificate        float64 `json:"certificate_key"`
	SignatureAlgorithm float64 `json:"signature_algorithm"`
}

type AnalysisSummary struct {
	AnalysisID       string         `json:"analysis_id"`
	TotalSessions    int            `json:"total_sessions"`
	ProtocolCounts   map[string]int `json:"protocol_counts"`
	TLSVersionCounts map[string]int `json:"tls_version_counts"`
	SeverityCounts   map[string]int `json:"severity_counts"`
	StartTLSCounts   map[string]int `json:"starttls_counts"`
}

// Future Modules 8-10 extension interfaces & models
type SessionFeatures struct {
	SessionID          string
	Protocol           string
	TLSVersion         string
	CipherStrength     string
	KeyLength          int
	CertificateAgeDays int
	ForwardSecrecy     bool
	HandshakeFailures  bool
	AlertCount         int
	PacketCount        int
	DurationMs         int64
}

type FeatureExtractor interface {
	Extract(session EmailSession) SessionFeatures
}

type AnomalyDetector interface {
	Score(features SessionFeatures) float64
}

type RiskClassifier interface {
	Classify(features SessionFeatures) string
}
