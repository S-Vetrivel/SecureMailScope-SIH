// Package models defines the API data transfer objects.
package models

import "time"

// Analysis represents a PCAP analysis job.
type Analysis struct {
	ID                  string                 `json:"id"`
	PcapFilename        string                 `json:"pcap_filename"`
	Status              string                 `json:"status"` // pending, processing, completed, failed
	OverallScore        float64                `json:"overall_score"`
	OverallSeverity     string                 `json:"overall_severity"`
	TotalSessions       int                    `json:"total_sessions"`
	TotalPackets        int                    `json:"total_packets"`
	SeverityBreakdown   map[string]int         `json:"severity_breakdown"`
	TLSVersionBreakdown map[string]int         `json:"tls_version_breakdown"`
	ProtocolBreakdown   map[string]int         `json:"protocol_breakdown"`
	AnomalyCount        int                    `json:"anomaly_count"`
	ForwardSecrecyPct   float64                `json:"forward_secrecy_pct"`
	ResultsJSON         map[string]interface{} `json:"results_json,omitempty"`
	CreatedAt           time.Time              `json:"created_at"`
	CompletedAt         *time.Time             `json:"completed_at,omitempty"`
}

// Session represents a single email communication session.
type Session struct {
	ID               string                   `json:"id"`
	AnalysisID       string                   `json:"analysis_id"`
	SessionKey       string                   `json:"session_key"`
	Protocol         string                   `json:"protocol"`
	SrcIP            string                   `json:"src_ip"`
	SrcPort          int                      `json:"src_port"`
	DstIP            string                   `json:"dst_ip"`
	DstPort          int                      `json:"dst_port"`
	TLSVersion       string                   `json:"tls_version"`
	NegotiatedCipher string                   `json:"negotiated_cipher"`
	HasForwardSecrecy bool                    `json:"has_forward_secrecy"`
	HasSTARTTLS      bool                     `json:"has_starttls"`
	IsEncrypted      bool                     `json:"is_encrypted"`
	RiskScore        float64                  `json:"risk_score"`
	Severity         string                   `json:"severity"`
	AnomalyScore     float64                  `json:"anomaly_score"`
	IsAnomalous      bool                     `json:"is_anomalous"`
	Findings         []map[string]interface{} `json:"findings"`
	Remediations     []map[string]interface{} `json:"remediations"`
	Scores           map[string]float64       `json:"scores"`
	CreatedAt        time.Time                `json:"created_at"`
}

// Certificate represents an X.509 certificate extracted from a session.
type Certificate struct {
	ID                 string    `json:"id"`
	SessionID          string    `json:"session_id"`
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
	DNSNames           []string  `json:"dns_names"`
}

// DashboardSummary provides aggregated statistics for the dashboard overview.
type DashboardSummary struct {
	TotalAnalyses        int                `json:"total_analyses"`
	TotalSessions        int                `json:"total_sessions"`
	AverageScore         float64            `json:"average_score"`
	OverallSeverity      string             `json:"overall_severity"`
	SeverityBreakdown    map[string]int     `json:"severity_breakdown"`
	TLSVersionBreakdown  map[string]int     `json:"tls_version_breakdown"`
	ProtocolBreakdown    map[string]int     `json:"protocol_breakdown"`
	TotalAnomalies       int                `json:"total_anomalies"`
	ForwardSecrecyPct    float64            `json:"forward_secrecy_pct"`
	RecentAnalyses       []Analysis         `json:"recent_analyses"`
	TopVulnerabilities   []VulnSummary      `json:"top_vulnerabilities"`
}

// VulnSummary aggregates a vulnerability type across sessions.
type VulnSummary struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	Count       int    `json:"count"`
}

// UploadResponse is returned after a successful PCAP upload.
type UploadResponse struct {
	AnalysisID string `json:"analysis_id"`
	Status     string `json:"status"`
	Message    string `json:"message"`
}
