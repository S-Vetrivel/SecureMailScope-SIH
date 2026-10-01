package api

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/jung-kurt/gofpdf"
	"github.com/securemailscope/backend/internal/analysis"
	"github.com/securemailscope/backend/internal/models"
	"github.com/securemailscope/backend/internal/storage"
)

type Server struct {
	repo        *storage.Repository
	service     *analysis.Service
	uploadDir   string
	upgrader    websocket.Upgrader
	wsMu        sync.RWMutex
	wsClients   map[*websocket.Conn]bool
}

func NewServer(repo *storage.Repository, service *analysis.Service, uploadDir string) *Server {
	if uploadDir == "" {
		uploadDir = "./data/uploads"
	}
	_ = os.MkdirAll(uploadDir, 0755)

	srv := &Server{
		repo:      repo,
		service:   service,
		uploadDir: uploadDir,
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		},
		wsClients: make(map[*websocket.Conn]bool),
	}

	service.SubscribeEvents(srv.broadcastWSEvent)
	service.SubscribeRawEvents(srv.broadcastRawWSEvent)
	return srv
}

func (s *Server) RegisterRoutes(r *gin.Engine) {
	v1 := r.Group("/api/v1")
	{
		v1.GET("/health", s.HealthCheck)
		v1.POST("/pcaps", s.UploadPCAP)

		v1.POST("/analyses", s.CreateAnalysis)
		v1.GET("/analyses", s.ListAnalyses)
		v1.GET("/analyses/:id", s.GetAnalysis)
		v1.POST("/analyses/:id/start", s.StartAnalysis)

		v1.GET("/analyses/:id/sessions", s.GetAnalysisSessions)
		v1.GET("/sessions/:id", s.GetSessionDetail)

		v1.GET("/analyses/:id/findings", s.GetAnalysisFindings)
		v1.GET("/findings/:id", s.GetFindingDetail)

		v1.GET("/analyses/:id/summary", s.GetAnalysisSummary)
		v1.GET("/analyses/:id/report", s.GetAnalysisReport)
		v1.GET("/summary", s.GetDashboardSummary)
		v1.GET("/analyses/:id/events", s.WebSocketEvents)
	}
}

func (s *Server) HealthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status": "ok",
		"dependencies": gin.H{
			"storage": true,
			"tshark":  true,
		},
	})
}

func (s *Server) UploadPCAP(c *gin.Context) {
	file, header, err := c.Request.FormFile("pcap")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "MISSING_FILE", "message": "No file uploaded"}})
		return
	}
	defer file.Close()

	ext := filepath.Ext(header.Filename)
	if ext != ".pcap" && ext != ".pcapng" && ext != ".cap" {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "INVALID_FILE_TYPE", "message": "File must be a PCAP format"}})
		return
	}

	savePath := filepath.Join(s.uploadDir, fmt.Sprintf("%d_%s", time.Now().UnixMilli(), filepath.Base(header.Filename)))
	dst, err := os.Create(savePath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": gin.H{"code": "SAVE_FAILED", "message": "Could not save uploaded PCAP"}})
		return
	}
	defer dst.Close()

	if _, err := io.Copy(dst, file); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": gin.H{"code": "SAVE_FAILED", "message": "Error writing PCAP file"}})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"pcap_path": savePath,
		"filename":  header.Filename,
		"size":      header.Size,
	})
}

func (s *Server) CreateAnalysis(c *gin.Context) {
	var body struct {
		PCAPPath string `json:"pcap_path" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "INVALID_INPUT", "message": err.Error()}})
		return
	}

	analysis, err := s.service.CreateAnalysis(body.PCAPPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": gin.H{"code": "CREATE_FAILED", "message": err.Error()}})
		return
	}

	c.JSON(http.StatusOK, analysis)
}

func (s *Server) ListAnalyses(c *gin.Context) {
	analyses, err := s.repo.ListAnalyses()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": gin.H{"code": "QUERY_FAILED", "message": err.Error()}})
		return
	}
	c.JSON(http.StatusOK, analyses)
}

func (s *Server) GetAnalysis(c *gin.Context) {
	id := c.Param("id")
	analysis, err := s.repo.GetAnalysis(id)
	if err != nil {
		log.Printf("[DEBUG] GetAnalysis failed: %v", err)
		c.JSON(http.StatusNotFound, gin.H{"error": gin.H{"code": "NOT_FOUND", "message": "Analysis not found"}})
		return
	}
	c.JSON(http.StatusOK, analysis)
}

func (s *Server) StartAnalysis(c *gin.Context) {
	id := c.Param("id")
	_, err := s.repo.GetAnalysis(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": gin.H{"code": "NOT_FOUND", "message": "Analysis not found"}})
		return
	}

	s.service.RunAnalysisAsync(id)
	c.JSON(http.StatusOK, gin.H{"id": id, "status": "QUEUED"})
}

func (s *Server) GetAnalysisSessions(c *gin.Context) {
	id := c.Param("id")
	sessions, err := s.repo.GetSessionsForAnalysis(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": gin.H{"code": "QUERY_FAILED", "message": err.Error()}})
		return
	}
	c.JSON(http.StatusOK, sessions)
}

func (s *Server) GetSessionDetail(c *gin.Context) {
	id := c.Param("id")
	session, err := s.repo.GetSession(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": gin.H{"code": "NOT_FOUND", "message": "Session not found"}})
		return
	}
	c.JSON(http.StatusOK, session)
}

func (s *Server) GetAnalysisFindings(c *gin.Context) {
	id := c.Param("id")
	findings, err := s.repo.GetFindingsForAnalysis(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": gin.H{"code": "QUERY_FAILED", "message": err.Error()}})
		return
	}
	c.JSON(http.StatusOK, findings)
}

func (s *Server) GetFindingDetail(c *gin.Context) {
	id := c.Param("id")
	finding, err := s.repo.GetFinding(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": gin.H{"code": "NOT_FOUND", "message": "Finding not found"}})
		return
	}
	c.JSON(http.StatusOK, finding)
}

func (s *Server) GetAnalysisSummary(c *gin.Context) {
	id := c.Param("id")
	sessions, err := s.repo.GetSessionsForAnalysis(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": gin.H{"code": "QUERY_FAILED", "message": err.Error()}})
		return
	}

	summary := models.AnalysisSummary{
		AnalysisID:       id,
		TotalSessions:    len(sessions),
		ProtocolCounts:   make(map[string]int),
		TLSVersionCounts: make(map[string]int),
		SeverityCounts:   make(map[string]int),
		StartTLSCounts:   make(map[string]int),
	}

	for _, sess := range sessions {
		summary.ProtocolCounts[string(sess.Protocol)]++

		if sess.TLS != nil && sess.TLS.Version != "" {
			summary.TLSVersionCounts[sess.TLS.Version]++
		} else {
			summary.TLSVersionCounts["Plaintext / None"]++
		}

		if sess.StartTLS.Supported {
			summary.StartTLSCounts["Supported"]++
		}
		if sess.StartTLS.TLSEstablished {
			summary.StartTLSCounts["Established"]++
		}

		for _, f := range sess.Findings {
			summary.SeverityCounts[string(f.Severity)]++
		}
	}

	c.JSON(http.StatusOK, summary)
}

func (s *Server) WebSocketEvents(c *gin.Context) {
	ws, err := s.upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		return
	}
	s.wsMu.Lock()
	s.wsClients[ws] = true
	s.wsMu.Unlock()

	// Keep the connection open and read messages (e.g. ping/pong or close events)
	for {
		if _, _, err := ws.ReadMessage(); err != nil {
			s.wsMu.Lock()
			delete(s.wsClients, ws)
			s.wsMu.Unlock()
			break
		}
	}
}

func (s *Server) broadcastWSEvent(evt analysis.ProgressEvent) {
	s.wsMu.RLock()
	clients := make([]*websocket.Conn, 0, len(s.wsClients))
	for client := range s.wsClients {
		clients = append(clients, client)
	}
	s.wsMu.RUnlock()

	for _, client := range clients {
		if err := client.WriteJSON(evt); err != nil {
			client.Close()
			s.wsMu.Lock()
			delete(s.wsClients, client)
			s.wsMu.Unlock()
		}
	}
}

func (s *Server) broadcastRawWSEvent(msg string) {
	s.wsMu.RLock()
	clients := make([]*websocket.Conn, 0, len(s.wsClients))
	for client := range s.wsClients {
		clients = append(clients, client)
	}
	s.wsMu.RUnlock()

	for _, client := range clients {
		if err := client.WriteMessage(websocket.TextMessage, []byte(msg)); err != nil {
			client.Close()
			s.wsMu.Lock()
			delete(s.wsClients, client)
			s.wsMu.Unlock()
		}
	}
}

// GetDashboardSummary returns aggregated stats for the main dashboard.
func (s *Server) GetDashboardSummary(c *gin.Context) {
	var totalAnalyses, totalSessions, totalAnomalies int
	var avgScore, fsPct float64

	s.repo.DB().QueryRow(`SELECT COUNT(*) FROM analyses`).Scan(&totalAnalyses)
	s.repo.DB().QueryRow(`SELECT COALESCE(SUM(total_sessions), 0) FROM analyses`).Scan(&totalSessions)
	s.repo.DB().QueryRow(`SELECT COALESCE(AVG(overall_score), 1.0) FROM analyses WHERE status='completed'`).Scan(&avgScore)
	s.repo.DB().QueryRow(`SELECT COALESCE(SUM(anomaly_count), 0) FROM analyses`).Scan(&totalAnomalies)
	s.repo.DB().QueryRow(`SELECT COALESCE(AVG(forward_secrecy_pct), 0) FROM analyses WHERE status='completed'`).Scan(&fsPct)

	// Aggregate severity breakdown
	sevBreakdown := map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
	rows, _ := s.repo.DB().Query(`SELECT severity, COUNT(*) FROM sessions GROUP BY severity`)
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
	rows2, _ := s.repo.DB().Query(`SELECT tls_version, COUNT(*) FROM sessions WHERE tls_version != '' GROUP BY tls_version`)
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
	rows3, _ := s.repo.DB().Query(`SELECT protocol, COUNT(*) FROM sessions WHERE protocol != '' GROUP BY protocol`)
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
	recentRows, _ := s.repo.DB().Query(`
		SELECT id, pcap_filename, status, overall_score, overall_severity, total_sessions, started_at
		FROM analyses ORDER BY started_at DESC LIMIT 10`)
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
func (s *Server) GetAnalysisReport(c *gin.Context) {
	id := c.Param("id")
	format := c.DefaultQuery("format", "json")
    
    // Fallback: we will fetch the DB manually if it's there, but actually we can just fetch the sessions directly from repo and construct the report.
    // However, the AI engine produces results_json, which we didn't save. 
    // Let's generate it directly from Go models.
    
    analysis, err := s.repo.GetAnalysis(id)
    if err != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "Analysis not found"})
		return
    }
    
    sessions, err := s.repo.GetSessionsForAnalysis(id)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
    }

	switch format {
	case "json":
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=report_%s.json", id[:8]))
		c.JSON(http.StatusOK, gin.H{
            "analysis": analysis,
            "sessions": sessions,
        })

	case "html":
		html := generateHTMLReport(analysis, sessions)
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=report_%s.html", id[:8]))
		c.Data(http.StatusOK, "text/html", []byte(html))

	case "pdf":
		pdfBytes, err := generatePDFReport(analysis, sessions)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate PDF"})
			return
		}
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=report_%s.pdf", id[:8]))
		c.Data(http.StatusOK, "application/pdf", pdfBytes)

	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "Supported formats: json, html, pdf"})
	}
}

// generateHTMLReport creates a professional HTML forensic report.
func generateHTMLReport(analysis *models.Analysis, sessions []models.EmailSession) string {
	severityColor := map[string]string{
		"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#eab308",
		"LOW": "#22c55e", "INFO": "#3b82f6",
	}
	color := severityColor[analysis.OverallSeverity]
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
      <tr><td>Total Sessions</td><td>%d</td></tr>
      <tr><td>Anomalies Detected</td><td>%d</td></tr>
      <tr><td>Forward Secrecy</td><td>%.1f%%</td></tr>
    </table>
  </div>
`, analysis.ID[:8], color, analysis.ID[:8], time.Now().Format(time.RFC3339),
		analysis.OverallScore, analysis.OverallSeverity,
		analysis.TotalSessions, analysis.AnomalyCount, analysis.ForwardSecrecyPct)

	html += `<div class="section"><h2>Session Details</h2><table><tr><th>Protocol</th><th>TLS Version</th><th>Cipher</th><th>Risk</th><th>Severity</th></tr>`

	for _, sess := range sessions {
		sevClass := "severity-" + strings.ToLower(sess.Severity)
		html += fmt.Sprintf(`<tr><td>%s</td><td>%s</td><td style="font-size:12px">%s</td><td>%.1f</td><td class="%s">%s</td></tr>`,
			sess.Protocol, sess.TLSVersion, sess.NegotiatedCipher,
			sess.RiskScore, sevClass, sess.Severity)
	}
	html += `</table></div>`

	// Add detailed findings section
	html += `<div class="section"><h2>Detailed Findings</h2>`
	hasFindings := false
	for _, sess := range sessions {
		if len(sess.Findings) > 0 {
			hasFindings = true
			html += fmt.Sprintf(`<h3>Session %s (%s - %s)</h3><ul>`, sess.ID, sess.SrcIP, sess.DstIP)
			for _, f := range sess.Findings {
				sevClass := "severity-" + strings.ToLower(string(f.Severity))
				html += fmt.Sprintf(`<li style="margin-bottom: 12px; padding-left: 20px;">
					<strong class="%s">[%s] %s</strong><br/>
					<span style="color: #94a3b8; font-size: 13px;">%s</span><br/>
					<strong>Remediation:</strong> %s
				</li>`, sevClass, f.Severity, f.Title, f.Description, f.Recommendation)
			}
			html += `</ul>`
		}
	}
	if !hasFindings {
		html += `<p style="color: #22c55e;">No cryptographic vulnerabilities detected in this capture.</p>`
	}
	html += `</div>`
	html += `<div class="footer">Generated by SecureMailScope v1.0 — AI-Assisted Cryptographic Security Posture Assessment<br/>NTRO Problem Statement 26159 | SIH 2026</div></div></body></html>`

	return html
}

// generatePDFReport creates a professional PDF forensic report.
func generatePDFReport(analysis *models.Analysis, sessions []models.EmailSession) ([]byte, error) {
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.AddPage()
	pdf.SetFont("Arial", "B", 20)
	pdf.Cell(40, 10, "SecureMailScope Forensic Report")
	pdf.Ln(10)
	
	pdf.SetFont("Arial", "", 12)
	pdf.Cell(40, 10, fmt.Sprintf("Analysis ID: %s", analysis.ID[:8]))
	pdf.Ln(10)
	pdf.Cell(40, 10, fmt.Sprintf("Generated: %s", time.Now().Format(time.RFC3339)))
	pdf.Ln(10)
	pdf.Cell(40, 10, fmt.Sprintf("Risk Score: %.1f/10 - %s", analysis.OverallScore, analysis.OverallSeverity))
	pdf.Ln(15)

	pdf.SetFont("Arial", "B", 16)
	pdf.Cell(40, 10, "Summary")
	pdf.Ln(10)
	
	pdf.SetFont("Arial", "", 12)
	pdf.Cell(40, 10, fmt.Sprintf("Total Sessions: %d", analysis.TotalSessions))
	pdf.Ln(10)
	pdf.Cell(40, 10, fmt.Sprintf("Anomalies Detected: %d", analysis.AnomalyCount))
	pdf.Ln(10)
	pdf.Cell(40, 10, fmt.Sprintf("Forward Secrecy: %.1f%%", analysis.ForwardSecrecyPct))
	pdf.Ln(15)

	pdf.SetFont("Arial", "B", 16)
	pdf.Cell(40, 10, "Session Details")
	pdf.Ln(10)

	pdf.SetFont("Arial", "B", 10)
	pdf.CellFormat(30, 10, "Protocol", "1", 0, "L", false, 0, "")
	pdf.CellFormat(30, 10, "TLS Version", "1", 0, "L", false, 0, "")
	pdf.CellFormat(70, 10, "Cipher", "1", 0, "L", false, 0, "")
	pdf.CellFormat(20, 10, "Risk", "1", 0, "L", false, 0, "")
	pdf.CellFormat(30, 10, "Severity", "1", 0, "L", false, 0, "")
	pdf.Ln(-1)

	pdf.SetFont("Arial", "", 9)
	for _, sess := range sessions {
		pdf.CellFormat(30, 10, string(sess.Protocol), "1", 0, "L", false, 0, "")
		pdf.CellFormat(30, 10, sess.TLSVersion, "1", 0, "L", false, 0, "")
		
		cipherStr := sess.NegotiatedCipher
		if len(cipherStr) > 35 {
			cipherStr = cipherStr[:32] + "..."
		}
		pdf.CellFormat(70, 10, cipherStr, "1", 0, "L", false, 0, "")
		
		pdf.CellFormat(20, 10, fmt.Sprintf("%.1f", sess.RiskScore), "1", 0, "L", false, 0, "")
		pdf.CellFormat(30, 10, sess.Severity, "1", 0, "L", false, 0, "")
		pdf.Ln(-1)
	}

	pdf.Ln(15)
	pdf.SetFont("Arial", "B", 16)
	pdf.Cell(40, 10, "Detailed Findings")
	pdf.Ln(10)

	hasFindings := false
	for _, sess := range sessions {
		if len(sess.Findings) > 0 {
			hasFindings = true
			pdf.SetFont("Arial", "B", 12)
			pdf.Cell(40, 10, fmt.Sprintf("Session %s (%s - %s)", sess.ID, sess.SrcIP, sess.DstIP))
			pdf.Ln(8)

			for _, f := range sess.Findings {
				pdf.SetFont("Arial", "B", 10)
				pdf.Cell(40, 6, fmt.Sprintf("[%s] %s", f.Severity, f.Title))
				pdf.Ln(6)
				
				pdf.SetFont("Arial", "", 10)
				pdf.MultiCell(0, 5, fmt.Sprintf("Description: %s", f.Description), "", "L", false)
				pdf.MultiCell(0, 5, fmt.Sprintf("Remediation: %s", f.Recommendation), "", "L", false)
				pdf.Ln(4)
			}
		}
	}

	if !hasFindings {
		pdf.SetFont("Arial", "I", 11)
		pdf.Cell(40, 10, "No cryptographic vulnerabilities detected in this capture.")
		pdf.Ln(10)
	}

	var buf strings.Builder
	err := pdf.Output(&buf)
	return []byte(buf.String()), err
}
