package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
	"github.com/securemailscope/backend/internal/models"
)

type Repository struct {
	db *sql.DB
}

func NewRepository(dbPath string) (*Repository, error) {
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create database directory: %w", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping sqlite database: %w", err)
	}

	repo := &Repository{db: db}
	if err := repo.initSchema(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	return repo, nil
}

func (r *Repository) Close() error {
	return r.db.Close()
}

func (r *Repository) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS analyses (
		id TEXT PRIMARY KEY,
		pcap_path TEXT NOT NULL,
		pcap_filename TEXT DEFAULT '',
		status TEXT NOT NULL,
		started_at DATETIME NOT NULL,
		finished_at DATETIME,
		total_packets INTEGER DEFAULT 0,
		total_sessions INTEGER DEFAULT 0,
		overall_score REAL DEFAULT 0,
		overall_severity TEXT DEFAULT 'INFO',
		forward_secrecy_pct REAL DEFAULT 0,
		severity_breakdown TEXT DEFAULT '{}',
		error TEXT
	);

	CREATE TABLE IF NOT EXISTS sessions (
		id TEXT PRIMARY KEY,
		analysis_id TEXT NOT NULL,
		client_ip TEXT NOT NULL,
		client_port INTEGER NOT NULL,
		server_ip TEXT NOT NULL,
		server_port INTEGER NOT NULL,
		protocol TEXT NOT NULL,
		start_time DATETIME NOT NULL,
		end_time DATETIME NOT NULL,
		packet_count INTEGER DEFAULT 0,
		client_bytes INTEGER DEFAULT 0,
		server_bytes INTEGER DEFAULT 0,
		stream_complete INTEGER DEFAULT 1,
		reassembly_gap INTEGER DEFAULT 0,
		starttls_json TEXT,
		tls_json TEXT,
		certificate_json TEXT,
		forward_secrecy TEXT NOT NULL,
		anomaly_score REAL DEFAULT 0,
		is_anomalous INTEGER DEFAULT 0,
		scores_json TEXT DEFAULT '{}',
		FOREIGN KEY(analysis_id) REFERENCES analyses(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS findings (
		id TEXT PRIMARY KEY,
		analysis_id TEXT NOT NULL,
		session_id TEXT NOT NULL,
		title TEXT NOT NULL,
		severity TEXT NOT NULL,
		category TEXT NOT NULL,
		description TEXT NOT NULL,
		evidence_json TEXT,
		recommendation TEXT NOT NULL,
		FOREIGN KEY(analysis_id) REFERENCES analyses(id) ON DELETE CASCADE,
		FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE
	);
	`
	_, err := r.db.Exec(schema)
	return err
}

func (r *Repository) CreateAnalysis(a *models.Analysis) error {
	query := `INSERT INTO analyses (id, pcap_path, pcap_filename, status, started_at, total_packets, total_sessions, severity_breakdown, error) 
	          VALUES (?, ?, ?, ?, ?, ?, ?, '{}', ?)`
	_, err := r.db.Exec(query, a.ID, a.PCAPPath, a.PCAPFilename, a.Status, a.StartedAt, a.TotalPackets, a.TotalSessions, a.Error)
	return err
}

func (r *Repository) UpdateAnalysisStatus(id string, status models.AnalysisStatus, errMsg string) error {
	var finishedAt *time.Time
	if status == models.StatusCompleted || status == models.StatusFailed {
		now := time.Now()
		finishedAt = &now
	}
	query := `UPDATE analyses SET status = ?, finished_at = ?, error = ? WHERE id = ?`
	_, err := r.db.Exec(query, status, finishedAt, errMsg, id)
	return err
}

func (r *Repository) UpdateAnalysisStats(id string, totalPackets, totalSessions int) error {
	query := `UPDATE analyses SET total_packets = ?, total_sessions = ? WHERE id = ?`
	_, err := r.db.Exec(query, totalPackets, totalSessions, id)
	return err
}

func (r *Repository) UpdateAnalysisAggregate(id string, status models.AnalysisStatus, overallScore, fsPct float64, severityBreakdown map[string]int) error {
	sevJSON, _ := json.Marshal(severityBreakdown)
	now := time.Now()

	// Compute severity label from score
	severity := "INFO"
	if overallScore >= 9 {
		severity = "CRITICAL"
	} else if overallScore >= 7 {
		severity = "HIGH"
	} else if overallScore >= 5 {
		severity = "MEDIUM"
	} else if overallScore >= 3 {
		severity = "LOW"
	}

	query := `UPDATE analyses SET status = ?, finished_at = ?, overall_score = ?, overall_severity = ?, forward_secrecy_pct = ?, severity_breakdown = ? WHERE id = ?`
	_, err := r.db.Exec(query, status, now, overallScore, severity, fsPct, string(sevJSON), id)
	return err
}


func (r *Repository) GetAnalysis(id string) (*models.Analysis, error) {
	query := `SELECT id, pcap_path, COALESCE(pcap_filename,''), status, started_at, finished_at, total_packets, total_sessions, COALESCE(overall_score,0), COALESCE(overall_severity,'INFO'), COALESCE(forward_secrecy_pct,0), COALESCE(severity_breakdown,'{}'), COALESCE(error,'') FROM analyses WHERE id = ?`
	row := r.db.QueryRow(query, id)

	var a models.Analysis
	var finishedAt sql.NullTime
	var sevBreakdownJSON string
	err := row.Scan(&a.ID, &a.PCAPPath, &a.PCAPFilename, &a.Status, &a.StartedAt, &finishedAt,
		&a.TotalPackets, &a.TotalSessions, &a.OverallScore, &a.OverallSeverity,
		&a.ForwardSecrecyPct, &sevBreakdownJSON, &a.Error)
	if err != nil {
		return nil, err
	}
	if finishedAt.Valid {
		a.FinishedAt = &finishedAt.Time
	}
	a.SeverityBreakdown = make(map[string]int)
	_ = json.Unmarshal([]byte(sevBreakdownJSON), &a.SeverityBreakdown)
	return &a, nil
}

func (r *Repository) ListAnalyses() ([]models.Analysis, error) {
	query := `SELECT id, pcap_path, COALESCE(pcap_filename,''), status, started_at, finished_at, total_packets, total_sessions, COALESCE(overall_score,0), COALESCE(overall_severity,'INFO'), COALESCE(forward_secrecy_pct,0), COALESCE(severity_breakdown,'{}'), COALESCE(error,'') FROM analyses ORDER BY started_at DESC`
	rows, err := r.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var analyses []models.Analysis
	for rows.Next() {
		var a models.Analysis
		var finishedAt sql.NullTime
		var sevBreakdownJSON string
		if err := rows.Scan(&a.ID, &a.PCAPPath, &a.PCAPFilename, &a.Status, &a.StartedAt, &finishedAt,
			&a.TotalPackets, &a.TotalSessions, &a.OverallScore, &a.OverallSeverity,
			&a.ForwardSecrecyPct, &sevBreakdownJSON, &a.Error); err != nil {
			continue
		}
		if finishedAt.Valid {
			a.FinishedAt = &finishedAt.Time
		}
		a.SeverityBreakdown = make(map[string]int)
		_ = json.Unmarshal([]byte(sevBreakdownJSON), &a.SeverityBreakdown)
		analyses = append(analyses, a)
	}
	return analyses, nil
}



func (r *Repository) SaveSession(s *models.EmailSession) error {
	startTLSJSON, _ := json.Marshal(s.StartTLS)
	var tlsJSON []byte
	if s.TLS != nil {
		tlsJSON, _ = json.Marshal(s.TLS)
	}
	var certJSON []byte
	if s.Certificate != nil {
		certJSON, _ = json.Marshal(s.Certificate)
	}

	streamComplete := 0
	if s.StreamComplete {
		streamComplete = 1
	}
	reassemblyGap := 0
	if s.ReassemblyGap {
		reassemblyGap = 1
	}
	isAnomalousInt := 0
	if s.IsAnomalous {
		isAnomalousInt = 1
	}
	scoresJSON, _ := json.Marshal(s.Scores)

	query := `INSERT OR REPLACE INTO sessions 
	(id, analysis_id, client_ip, client_port, server_ip, server_port, protocol, start_time, end_time, packet_count, client_bytes, server_bytes, stream_complete, reassembly_gap, starttls_json, tls_json, certificate_json, forward_secrecy, anomaly_score, is_anomalous, scores_json)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := r.db.Exec(query,
		s.ID, s.AnalysisID, s.Client.IP, s.Client.Port, s.Server.IP, s.Server.Port,
		string(s.Protocol), s.StartTime, s.EndTime, s.PacketCount, s.ClientBytes, s.ServerBytes,
		streamComplete, reassemblyGap, string(startTLSJSON), string(tlsJSON), string(certJSON), string(s.ForwardSecrecy),
		s.AnomalyScore, isAnomalousInt, string(scoresJSON),
	)
	if err != nil {
		return err
	}

	for _, f := range s.Findings {
		if err := r.SaveFinding(s.AnalysisID, &f); err != nil {
			return err
		}
	}
	return nil
}

func (r *Repository) SaveFinding(analysisID string, f *models.Finding) error {
	evJSON, _ := json.Marshal(f.Evidence)
	query := `INSERT OR REPLACE INTO findings 
	(id, analysis_id, session_id, title, severity, category, description, evidence_json, recommendation)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
	_, err := r.db.Exec(query, f.ID, analysisID, f.SessionID, f.Title, string(f.Severity), f.Category, f.Description, string(evJSON), f.Recommendation)
	return err
}

func (r *Repository) GetSessionsForAnalysis(analysisID string) ([]models.EmailSession, error) {
	query := `SELECT id, analysis_id, client_ip, client_port, server_ip, server_port, protocol, start_time, end_time, packet_count, client_bytes, server_bytes, stream_complete, reassembly_gap, starttls_json, tls_json, certificate_json, forward_secrecy, anomaly_score, is_anomalous, scores_json FROM sessions WHERE analysis_id = ?`
	rows, err := r.db.Query(query, analysisID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []models.EmailSession
	for rows.Next() {
		var s models.EmailSession
		var protoStr, fwSecStr, starttlsStr, tlsStr, certStr, scoresStr string
		var streamCompleteInt, reassemblyGapInt, isAnomalousInt int

		err := rows.Scan(
			&s.ID, &s.AnalysisID, &s.Client.IP, &s.Client.Port, &s.Server.IP, &s.Server.Port,
			&protoStr, &s.StartTime, &s.EndTime, &s.PacketCount, &s.ClientBytes, &s.ServerBytes,
			&streamCompleteInt, &reassemblyGapInt, &starttlsStr, &tlsStr, &certStr, &fwSecStr,
			&s.AnomalyScore, &isAnomalousInt, &scoresStr,
		)
		if err != nil {
			return nil, err
		}

		s.Protocol = models.EmailProtocol(protoStr)
		s.ForwardSecrecy = models.ForwardSecrecyStatus(fwSecStr)
		s.StreamComplete = streamCompleteInt == 1
		s.ReassemblyGap = reassemblyGapInt == 1
		s.IsAnomalous = isAnomalousInt == 1

		if starttlsStr != "" {
			_ = json.Unmarshal([]byte(starttlsStr), &s.StartTLS)
		}
		if tlsStr != "" {
			var t models.TLSInfo
			if json.Unmarshal([]byte(tlsStr), &t) == nil {
				s.TLS = &t
			}
		}
		if certStr != "" {
			var c models.CertificateInfo
			if json.Unmarshal([]byte(certStr), &c) == nil {
				s.Certificate = &c
			}
		}
		if scoresStr != "" {
			_ = json.Unmarshal([]byte(scoresStr), &s.Scores)
		}

		findings, _ := r.GetFindingsForSession(s.ID)
		s.Findings = findings

		// Populate dashboard-friendly flat fields
		s.SessionID = s.ID
		s.SrcIP = s.Client.IP
		s.DstIP = s.Server.IP
		if s.TLS != nil {
			s.TLSVersion = s.TLS.Version
			s.NegotiatedCipher = s.TLS.CipherSuite
			s.SignatureAlgorithm = s.TLS.SignatureAlgorithm
		}
		s.HasForwardSecrecy = s.ForwardSecrecy == models.ForwardSecrecyStatus("YES")
		// Risk score from findings
		maxScore := 0.0
		maxSev := "INFO"
		for _, f := range s.Findings {
			sc := severityToScore(f.Severity)
			if sc > maxScore {
				maxScore = sc
				maxSev = string(f.Severity)
			}
		}
		s.RiskScore = maxScore
		s.Severity = maxSev

		sessions = append(sessions, s)
	}
	return sessions, nil
}

func (r *Repository) GetSession(sessionID string) (*models.EmailSession, error) {
	query := `SELECT id, analysis_id, client_ip, client_port, server_ip, server_port, protocol, start_time, end_time, packet_count, client_bytes, server_bytes, stream_complete, reassembly_gap, starttls_json, tls_json, certificate_json, forward_secrecy FROM sessions WHERE id = ?`
	row := r.db.QueryRow(query, sessionID)

	var s models.EmailSession
	var protoStr, fwSecStr, starttlsStr, tlsStr, certStr string
	var streamCompleteInt, reassemblyGapInt int

	err := row.Scan(
		&s.ID, &s.AnalysisID, &s.Client.IP, &s.Client.Port, &s.Server.IP, &s.Server.Port,
		&protoStr, &s.StartTime, &s.EndTime, &s.PacketCount, &s.ClientBytes, &s.ServerBytes,
		&streamCompleteInt, &reassemblyGapInt, &starttlsStr, &tlsStr, &certStr, &fwSecStr,
	)
	if err != nil {
		return nil, err
	}

	s.Protocol = models.EmailProtocol(protoStr)
	s.ForwardSecrecy = models.ForwardSecrecyStatus(fwSecStr)
	s.StreamComplete = streamCompleteInt == 1
	s.ReassemblyGap = reassemblyGapInt == 1

	if starttlsStr != "" {
		_ = json.Unmarshal([]byte(starttlsStr), &s.StartTLS)
	}
	if tlsStr != "" {
		var t models.TLSInfo
		if json.Unmarshal([]byte(tlsStr), &t) == nil {
			s.TLS = &t
		}
	}
	if certStr != "" {
		var c models.CertificateInfo
		if json.Unmarshal([]byte(certStr), &c) == nil {
			s.Certificate = &c
		}
	}

	findings, _ := r.GetFindingsForSession(s.ID)
	s.Findings = findings

	// Populate flat fields
	s.SessionID = s.ID
	s.SrcIP = s.Client.IP
	s.DstIP = s.Server.IP
	if s.TLS != nil {
		s.TLSVersion = s.TLS.Version
		s.NegotiatedCipher = s.TLS.CipherSuite
		s.SignatureAlgorithm = s.TLS.SignatureAlgorithm
	}
	s.HasForwardSecrecy = s.ForwardSecrecy == models.ForwardSecrecyStatus("YES")

	return &s, nil
}

func (r *Repository) GetFindingsForSession(sessionID string) ([]models.Finding, error) {
	query := `SELECT id, title, severity, category, session_id, description, evidence_json, recommendation FROM findings WHERE session_id = ?`
	rows, err := r.db.Query(query, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var findings []models.Finding
	for rows.Next() {
		var f models.Finding
		var sevStr, evStr string
		if err := rows.Scan(&f.ID, &f.Title, &sevStr, &f.Category, &f.SessionID, &f.Description, &evStr, &f.Recommendation); err != nil {
			return nil, err
		}
		f.Severity = models.Severity(sevStr)
		_ = json.Unmarshal([]byte(evStr), &f.Evidence)
		findings = append(findings, f)
	}
	return findings, nil
}

func (r *Repository) GetFindingsForAnalysis(analysisID string) ([]models.Finding, error) {
	query := `SELECT id, title, severity, category, session_id, description, evidence_json, recommendation FROM findings WHERE analysis_id = ?`
	rows, err := r.db.Query(query, analysisID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var findings []models.Finding
	for rows.Next() {
		var f models.Finding
		var sevStr, evStr string
		if err := rows.Scan(&f.ID, &f.Title, &sevStr, &f.Category, &f.SessionID, &f.Description, &evStr, &f.Recommendation); err != nil {
			return nil, err
		}
		f.Severity = models.Severity(sevStr)
		_ = json.Unmarshal([]byte(evStr), &f.Evidence)
		findings = append(findings, f)
	}
	return findings, nil
}

func (r *Repository) GetFinding(id string) (*models.Finding, error) {
	query := `SELECT id, title, severity, category, session_id, description, evidence_json, recommendation FROM findings WHERE id = ?`
	row := r.db.QueryRow(query, id)

	var f models.Finding
	var sevStr, evStr string
	if err := row.Scan(&f.ID, &f.Title, &sevStr, &f.Category, &f.SessionID, &f.Description, &evStr, &f.Recommendation); err != nil {
		return nil, err
	}
	f.Severity = models.Severity(sevStr)
	_ = json.Unmarshal([]byte(evStr), &f.Evidence)
	return &f, nil
}

func severityToScore(sev models.Severity) float64 {
	switch sev {
	case models.SeverityCritical:
		return 9.0
	case models.SeverityHigh:
		return 7.0
	case models.SeverityMedium:
		return 5.0
	case models.SeverityLow:
		return 3.0
	default:
		return 1.0
	}
}

