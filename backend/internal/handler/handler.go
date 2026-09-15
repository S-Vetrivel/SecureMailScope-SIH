// Package handler provides HTTP request handlers for the SecureMailScope API.
package handler

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/securemailscope/backend/internal/db"
)

// UploadPCAP handles multipart PCAP file uploads and triggers the analysis pipeline.
func UploadPCAP(c *gin.Context) {
	file, header, err := c.Request.FormFile("pcap")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No PCAP file provided"})
		return
	}
	defer file.Close()

	// Validate file extension
	ext := filepath.Ext(header.Filename)
	if ext != ".pcap" && ext != ".pcapng" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Only .pcap and .pcapng files are accepted"})
		return
	}

	// Generate analysis ID
	analysisID := uuid.New().String()

	// Save uploaded file
	uploadDir := filepath.Join("uploads", analysisID)
	if err := os.MkdirAll(uploadDir, 0755); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create upload directory"})
		return
	}

	pcapPath := filepath.Join(uploadDir, header.Filename)
	dst, err := os.Create(pcapPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save file"})
		return
	}

	if _, err := io.Copy(dst, file); err != nil {
		dst.Close()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to write file"})
		return
	}
	dst.Close()

	// Insert analysis record into database
	_, err = db.DB.Exec(
		`INSERT INTO analyses (id, pcap_filename, status, created_at) VALUES ($1, $2, 'pending', $3)`,
		analysisID, header.Filename, time.Now(),
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create analysis record"})
		return
	}

	// Trigger async analysis pipeline
	go runPipeline(analysisID, pcapPath)

	c.JSON(http.StatusAccepted, gin.H{
		"analysis_id": analysisID,
		"status":      "pending",
		"message":     "PCAP uploaded successfully. Analysis pipeline started.",
	})
}

// runPipeline executes the analysis pipeline: Go parser → Python AI engine → DB storage.
func runPipeline(analysisID, pcapPath string) {
	log.Printf("[Pipeline] Starting analysis %s for %s", analysisID, pcapPath)

	// Update status to processing
	db.DB.Exec(`UPDATE analyses SET status = 'processing' WHERE id = $1`, analysisID)

	uploadDir, _ := filepath.Abs(filepath.Dir(pcapPath))
	absPcapPath, _ := filepath.Abs(pcapPath)
	sessionsPath := filepath.Join(uploadDir, "sessions.json")
	resultsPath := filepath.Join(uploadDir, "results.json")

	parserBin := resolveBinary("parser")
	aiScript := resolvePath(filepath.Join("ai_engine", "main.py"))

	// Step 1: Run Go PCAP parser
	log.Printf("[Pipeline] Step 1: Running PCAP parser (%s)...", parserBin)
	parserCmd := exec.Command(
		parserBin,
		"--pcap", absPcapPath,
		"--output", sessionsPath,
	)
	parserCmd.Dir = uploadDir
	if output, err := parserCmd.CombinedOutput(); err != nil {
		log.Printf("[Pipeline] Parser failed: %v\nOutput: %s", err, string(output))
		db.DB.Exec(`UPDATE analyses SET status = 'failed' WHERE id = $1`, analysisID)
		return
	}

	// Step 2: Run Python AI engine
	log.Printf("[Pipeline] Step 2: Running AI risk engine (%s)...", aiScript)
	aiCmd := exec.Command(
		"python3", aiScript,
		"--input", sessionsPath,
		"--output", resultsPath,
	)
	aiCmd.Dir = uploadDir
	if output, err := aiCmd.CombinedOutput(); err != nil {
		log.Printf("[Pipeline] AI engine failed: %v\nOutput: %s", err, string(output))
		db.DB.Exec(`UPDATE analyses SET status = 'failed' WHERE id = $1`, analysisID)
		return
	}

	// Step 3: Parse results and store in DB
	log.Printf("[Pipeline] Step 3: Storing results...")
	if err := storeResults(analysisID, resultsPath, sessionsPath); err != nil {
		log.Printf("[Pipeline] Failed to store results: %v", err)
		db.DB.Exec(`UPDATE analyses SET status = 'failed' WHERE id = $1`, analysisID)
		return
	}

	log.Printf("[Pipeline] Analysis %s completed successfully", analysisID)
}

// storeResults reads the AI engine output and inserts it into PostgreSQL.
func storeResults(analysisID, resultsPath, sessionsPath string) error {
	// Read results
	resultsData, err := os.ReadFile(resultsPath)
	if err != nil {
		return fmt.Errorf("failed to read results: %w", err)
	}

	var results map[string]interface{}
	if err := json.Unmarshal(resultsData, &results); err != nil {
		return fmt.Errorf("failed to parse results: %w", err)
	}

	// Read sessions for packet count
	sessionsData, err := os.ReadFile(sessionsPath)
	if err != nil {
		return fmt.Errorf("failed to read sessions: %w", err)
	}

	var parsedSessions map[string]interface{}
	if err := json.Unmarshal(sessionsData, &parsedSessions); err != nil {
		return fmt.Errorf("failed to parse sessions: %w", err)
	}

	totalPackets := 0
	if tp, ok := parsedSessions["total_packets"].(float64); ok {
		totalPackets = int(tp)
	}

	// Extract summary
	summary, _ := results["summary"].(map[string]interface{})
	overallScore := getFloat(summary, "overall_score", 1.0)
	overallSeverity := getString(summary, "overall_severity", "INFO")
	totalSessions := getInt(summary, "total_sessions", 0)
	anomalyCount := getInt(summary, "anomaly_count", 0)
	fsPct := getFloat(summary, "forward_secrecy_percentage", 0)

	sevBreakdown, _ := json.Marshal(summary["severity_breakdown"])
	tlsBreakdown, _ := json.Marshal(summary["tls_version_breakdown"])
	protoBreakdown, _ := json.Marshal(summary["protocol_breakdown"])
	resultsJSON, _ := json.Marshal(results)

	now := time.Now()

	// Update analysis record
	_, err = db.DB.Exec(`
		UPDATE analyses SET
			status = 'completed',
			overall_score = $1,
			overall_severity = $2,
			total_sessions = $3,
			total_packets = $4,
			severity_breakdown = $5,
			tls_version_breakdown = $6,
			protocol_breakdown = $7,
			anomaly_count = $8,
			forward_secrecy_pct = $9,
			results_json = $10,
			completed_at = $11
		WHERE id = $12`,
		overallScore, overallSeverity, totalSessions, totalPackets,
		string(sevBreakdown), string(tlsBreakdown), string(protoBreakdown),
		anomalyCount, fsPct, string(resultsJSON), now, analysisID,
	)
	if err != nil {
		return fmt.Errorf("failed to update analysis: %w", err)
	}

	// Store individual sessions
	sessions, ok := results["sessions"].([]interface{})
	if ok {
		for _, s := range sessions {
			sess, ok := s.(map[string]interface{})
			if !ok {
				continue
			}
			sessionID := uuid.New().String()
			sessionKey := getString(sess, "session_id", "")
			findingsJSON, _ := json.Marshal(sess["findings"])
			remsJSON, _ := json.Marshal(sess["remediations"])
			scoresJSON, _ := json.Marshal(sess["scores"])

			_, err := db.DB.Exec(`
				INSERT INTO sessions (
					id, analysis_id, session_key, protocol, src_ip, dst_ip,
					tls_version, negotiated_cipher, has_forward_secrecy,
					risk_score, severity, anomaly_score, is_anomalous,
					findings, remediations, scores, created_at
				) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`,
				sessionID, analysisID, sessionKey,
				getString(sess, "protocol", ""),
				getString(sess, "src_ip", ""),
				getString(sess, "dst_ip", ""),
				getString(sess, "tls_version", ""),
				getString(sess, "negotiated_cipher", ""),
				getBool(sess, "has_forward_secrecy", false),
				getFloat(sess, "risk_score", 1.0),
				getString(sess, "severity", "INFO"),
				getFloat(sess, "anomaly_score", 0),
				getBool(sess, "is_anomalous", false),
				string(findingsJSON), string(remsJSON), string(scoresJSON),
				time.Now(),
			)
			if err != nil {
				log.Printf("[Pipeline] Warning: failed to insert session %s: %v", sessionKey, err)
			}
		}
	}

	return nil
}

// GetAnalyses returns a list of all analyses, most recent first.
func GetAnalyses(c *gin.Context) {
	rows, err := db.DB.Query(`
		SELECT id, pcap_filename, status, overall_score, overall_severity,
			   total_sessions, total_packets, anomaly_count, created_at, completed_at
		FROM analyses ORDER BY created_at DESC LIMIT 50`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	analyses := []gin.H{}
	for rows.Next() {
		var id, filename, status, severity string
		var score float64
		var sessions, packets, anomalies int
		var createdAt time.Time
		var completedAt sql.NullTime

		rows.Scan(&id, &filename, &status, &score, &severity,
			&sessions, &packets, &anomalies, &createdAt, &completedAt)

		a := gin.H{
			"id": id, "pcap_filename": filename, "status": status,
			"overall_score": score, "overall_severity": severity,
			"total_sessions": sessions, "total_packets": packets,
			"anomaly_count": anomalies, "created_at": createdAt,
		}
		if completedAt.Valid {
			a["completed_at"] = completedAt.Time
		}
		analyses = append(analyses, a)
	}

	c.JSON(http.StatusOK, gin.H{"analyses": analyses})
}

// GetAnalysis returns the full details of a single analysis.
func GetAnalysis(c *gin.Context) {
	id := c.Param("id")

	var resultsJSON string
	var pcapFilename, status, severity string
	var score, fsPct float64
	var totalSessions, totalPackets, anomalyCount int
	var sevBreakdown, tlsBreakdown, protoBreakdown string
	var createdAt time.Time
	var completedAt sql.NullTime

	err := db.DB.QueryRow(`
		SELECT pcap_filename, status, overall_score, overall_severity,
			   total_sessions, total_packets, severity_breakdown,
			   tls_version_breakdown, protocol_breakdown,
			   anomaly_count, forward_secrecy_pct, results_json,
			   created_at, completed_at
		FROM analyses WHERE id = $1`, id).Scan(
		&pcapFilename, &status, &score, &severity,
		&totalSessions, &totalPackets, &sevBreakdown,
		&tlsBreakdown, &protoBreakdown,
		&anomalyCount, &fsPct, &resultsJSON,
		&createdAt, &completedAt,
	)
	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "Analysis not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	var results map[string]interface{}
	json.Unmarshal([]byte(resultsJSON), &results)

	var sevMap, tlsMap, protoMap map[string]interface{}
	json.Unmarshal([]byte(sevBreakdown), &sevMap)
	json.Unmarshal([]byte(tlsBreakdown), &tlsMap)
	json.Unmarshal([]byte(protoBreakdown), &protoMap)

	resp := gin.H{
		"id": id, "pcap_filename": pcapFilename, "status": status,
		"overall_score": score, "overall_severity": severity,
		"total_sessions": totalSessions, "total_packets": totalPackets,
		"severity_breakdown": sevMap, "tls_version_breakdown": tlsMap,
		"protocol_breakdown": protoMap, "anomaly_count": anomalyCount,
		"forward_secrecy_pct": fsPct, "results": results,
		"created_at": createdAt,
	}
	if completedAt.Valid {
		resp["completed_at"] = completedAt.Time
	}

	c.JSON(http.StatusOK, resp)
}

// GetAnalysisSessions returns sessions belonging to a specific analysis.
func GetAnalysisSessions(c *gin.Context) {
	analysisID := c.Param("id")

	rows, err := db.DB.Query(`
		SELECT id, session_key, protocol, src_ip, dst_ip,
			   tls_version, negotiated_cipher, has_forward_secrecy,
			   risk_score, severity, anomaly_score, is_anomalous,
			   findings, remediations, scores
		FROM sessions WHERE analysis_id = $1 ORDER BY risk_score DESC`, analysisID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	sessions := []gin.H{}
	for rows.Next() {
		var id, key, proto, srcIP, dstIP, tlsVer, cipher, sev string
		var hasFS, isAnomaly bool
		var riskScore, anomalyScore float64
		var findingsStr, remsStr, scoresStr string

		rows.Scan(&id, &key, &proto, &srcIP, &dstIP,
			&tlsVer, &cipher, &hasFS, &riskScore, &sev,
			&anomalyScore, &isAnomaly, &findingsStr, &remsStr, &scoresStr)

		var findings, rems []interface{}
		var scores map[string]interface{}
		json.Unmarshal([]byte(findingsStr), &findings)
		json.Unmarshal([]byte(remsStr), &rems)
		json.Unmarshal([]byte(scoresStr), &scores)

		sessions = append(sessions, gin.H{
			"id": id, "session_key": key, "protocol": proto,
			"src_ip": srcIP, "dst_ip": dstIP,
			"tls_version": tlsVer, "negotiated_cipher": cipher,
			"has_forward_secrecy": hasFS, "risk_score": riskScore,
			"severity": sev, "anomaly_score": anomalyScore,
			"is_anomalous": isAnomaly, "findings": findings,
			"remediations": rems, "scores": scores,
		})
	}

	c.JSON(http.StatusOK, gin.H{"sessions": sessions})
}

// GetDashboardSummary returns aggregated stats for the main dashboard.
func GetDashboardSummary(c *gin.Context) {
	var totalAnalyses, totalSessions, totalAnomalies int
	var avgScore, fsPct float64

	db.DB.QueryRow(`SELECT COUNT(*) FROM analyses`).Scan(&totalAnalyses)
	db.DB.QueryRow(`SELECT COALESCE(SUM(total_sessions), 0) FROM analyses`).Scan(&totalSessions)
	db.DB.QueryRow(`SELECT COALESCE(AVG(overall_score), 1.0) FROM analyses WHERE status='completed'`).Scan(&avgScore)
	db.DB.QueryRow(`SELECT COALESCE(SUM(anomaly_count), 0) FROM analyses`).Scan(&totalAnomalies)
	db.DB.QueryRow(`SELECT COALESCE(AVG(forward_secrecy_pct), 0) FROM analyses WHERE status='completed'`).Scan(&fsPct)

	// Aggregate severity breakdown
	sevBreakdown := map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
	rows, _ := db.DB.Query(`SELECT severity, COUNT(*) FROM sessions GROUP BY severity`)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var sev string
			var count int
			rows.Scan(&sev, &count)
			sevBreakdown[sev] = count
		}
	}

	// TLS version breakdown
	tlsBreakdown := map[string]int{}
	rows2, _ := db.DB.Query(`SELECT tls_version, COUNT(*) FROM sessions WHERE tls_version != '' GROUP BY tls_version`)
	if rows2 != nil {
		defer rows2.Close()
		for rows2.Next() {
			var ver string
			var count int
			rows2.Scan(&ver, &count)
			tlsBreakdown[ver] = count
		}
	}

	// Protocol breakdown
	protoBreakdown := map[string]int{}
	rows3, _ := db.DB.Query(`SELECT protocol, COUNT(*) FROM sessions WHERE protocol != '' GROUP BY protocol`)
	if rows3 != nil {
		defer rows3.Close()
		for rows3.Next() {
			var proto string
			var count int
			rows3.Scan(&proto, &count)
			protoBreakdown[proto] = count
		}
	}

	// Recent analyses
	recentRows, _ := db.DB.Query(`
		SELECT id, pcap_filename, status, overall_score, overall_severity, total_sessions, created_at
		FROM analyses ORDER BY created_at DESC LIMIT 10`)
	recent := []gin.H{}
	if recentRows != nil {
		defer recentRows.Close()
		for recentRows.Next() {
			var id, fn, status, sev string
			var score float64
			var sessions int
			var created time.Time
			recentRows.Scan(&id, &fn, &status, &score, &sev, &sessions, &created)
			recent = append(recent, gin.H{
				"id": id, "pcap_filename": fn, "status": status,
				"overall_score": score, "overall_severity": sev,
				"total_sessions": sessions, "created_at": created,
			})
		}
	}

	severity := "INFO"
	if avgScore >= 8 {
		severity = "CRITICAL"
	} else if avgScore >= 6 {
		severity = "HIGH"
	} else if avgScore >= 4 {
		severity = "MEDIUM"
	} else if avgScore >= 2 {
		severity = "LOW"
	}

	c.JSON(http.StatusOK, gin.H{
		"total_analyses":        totalAnalyses,
		"total_sessions":        totalSessions,
		"average_score":         avgScore,
		"overall_severity":      severity,
		"severity_breakdown":    sevBreakdown,
		"tls_version_breakdown": tlsBreakdown,
		"protocol_breakdown":    protoBreakdown,
		"total_anomalies":       totalAnomalies,
		"forward_secrecy_pct":   fsPct,
		"recent_analyses":       recent,
	})
}

// GetAnalysisReport generates an exportable report for the given analysis.
func GetAnalysisReport(c *gin.Context) {
	id := c.Param("id")
	format := c.DefaultQuery("format", "json")

	var resultsJSON string
	err := db.DB.QueryRow(`SELECT results_json FROM analyses WHERE id = $1`, id).Scan(&resultsJSON)
	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "Analysis not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	switch format {
	case "json":
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=report_%s.json", id[:8]))
		c.Data(http.StatusOK, "application/json", []byte(resultsJSON))

	case "html":
		var results map[string]interface{}
		json.Unmarshal([]byte(resultsJSON), &results)
		html := generateHTMLReport(id, results)
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=report_%s.html", id[:8]))
		c.Data(http.StatusOK, "text/html", []byte(html))

	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "Supported formats: json, html"})
	}
}

// generateHTMLReport creates a professional HTML forensic report.
func generateHTMLReport(analysisID string, results map[string]interface{}) string {
	summary, _ := results["summary"].(map[string]interface{})
	score := getFloat(summary, "overall_score", 0)
	severity := getString(summary, "overall_severity", "INFO")

	severityColor := map[string]string{
		"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#eab308",
		"LOW": "#22c55e", "INFO": "#3b82f6",
	}
	color := severityColor[severity]
	if color == "" {
		color = "#6b7280"
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SecureMailScope Forensic Report — %s</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'Segoe UI', system-ui, sans-serif; background: #0f172a; color: #e2e8f0; line-height: 1.6; }
  .container { max-width: 1000px; margin: 0 auto; padding: 40px 20px; }
  .header { text-align: center; margin-bottom: 40px; border-bottom: 2px solid #334155; padding-bottom: 30px; }
  .header h1 { font-size: 28px; color: #f1f5f9; margin-bottom: 8px; }
  .header .subtitle { color: #94a3b8; font-size: 14px; }
  .score-badge { display: inline-block; background: %s; color: white; padding: 8px 24px; border-radius: 999px; font-size: 24px; font-weight: bold; margin: 16px 0; }
  .section { margin-bottom: 32px; background: #1e293b; border-radius: 12px; padding: 24px; border: 1px solid #334155; }
  .section h2 { color: #f1f5f9; font-size: 20px; margin-bottom: 16px; border-bottom: 1px solid #334155; padding-bottom: 8px; }
  table { width: 100%%; border-collapse: collapse; }
  th, td { padding: 10px 14px; text-align: left; border-bottom: 1px solid #334155; }
  th { color: #94a3b8; font-weight: 600; font-size: 13px; text-transform: uppercase; }
  .severity-critical { color: #ef4444; font-weight: bold; }
  .severity-high { color: #f97316; font-weight: bold; }
  .severity-medium { color: #eab308; }
  .severity-low { color: #22c55e; }
  .severity-info { color: #3b82f6; }
  .footer { text-align: center; color: #64748b; font-size: 13px; margin-top: 40px; padding-top: 20px; border-top: 1px solid #334155; }
  @media print { body { background: white; color: #1e293b; } .section { border-color: #e2e8f0; } }
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>🔒 SecureMailScope Forensic Report</h1>
    <div class="subtitle">Analysis ID: %s | Generated: %s</div>
    <div class="score-badge">Risk Score: %.1f/10 — %s</div>
  </div>
  <div class="section">
    <h2>Summary</h2>
    <table>
      <tr><td>Total Sessions</td><td>%v</td></tr>
      <tr><td>Anomalies Detected</td><td>%v</td></tr>
      <tr><td>Forward Secrecy</td><td>%v%%</td></tr>
    </table>
  </div>
`, analysisID[:8], color, analysisID[:8], time.Now().Format(time.RFC3339),
		score, severity,
		summary["total_sessions"], summary["anomaly_count"], summary["forward_secrecy_percentage"])

	// Add sessions table
	html += `<div class="section"><h2>Session Details</h2><table><tr><th>Protocol</th><th>TLS Version</th><th>Cipher</th><th>Risk</th><th>Severity</th></tr>`

	if sessions, ok := results["sessions"].([]interface{}); ok {
		for _, s := range sessions {
			sess, ok := s.(map[string]interface{})
			if !ok {
				continue
			}
			sev := getString(sess, "severity", "INFO")
			sevClass := "severity-" + strings.ToLower(sev)
			html += fmt.Sprintf(`<tr><td>%s</td><td>%s</td><td style="font-size:12px">%s</td><td>%.1f</td><td class="%s">%s</td></tr>`,
				sess["protocol"], sess["tls_version"], sess["negotiated_cipher"],
				getFloat(sess, "risk_score", 0), sevClass, sev)
		}
	}
	html += `</table></div>`

	html += `<div class="footer">Generated by SecureMailScope v1.0 — AI-Assisted Cryptographic Security Posture Assessment<br/>NTRO Problem Statement 26159 | SIH 2026</div></div></body></html>`

	return html
}

// Helper functions for safe type assertions
func getString(m map[string]interface{}, key, fallback string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return fallback
}

func getFloat(m map[string]interface{}, key string, fallback float64) float64 {
	if v, ok := m[key].(float64); ok {
		return v
	}
	return fallback
}

func getInt(m map[string]interface{}, key string, fallback int) int {
	if v, ok := m[key].(float64); ok {
		return int(v)
	}
	return fallback
}

func getBool(m map[string]interface{}, key string, fallback bool) bool {
	if v, ok := m[key].(bool); ok {
		return v
	}
	return fallback
}

func resolveBinary(name string) string {
	cwd, _ := os.Getwd()
	candidates := []string{
		filepath.Join(cwd, "bin", name),
		filepath.Join(cwd, "..", "bin", name),
		filepath.Join(cwd, "..", "..", "bin", name),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return name
}

func resolvePath(relPath string) string {
	cwd, _ := os.Getwd()
	candidates := []string{
		filepath.Join(cwd, relPath),
		filepath.Join(cwd, "..", relPath),
		filepath.Join(cwd, "..", "..", relPath),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return relPath
}
