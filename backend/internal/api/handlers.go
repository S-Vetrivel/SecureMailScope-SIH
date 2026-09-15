package api

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
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
