// SecureMailScope API Server
//
// Provides REST API for the SecureMailScope dashboard:
// - PCAP upload and analysis pipeline orchestration
// - Analysis results retrieval
// - Dashboard summary statistics
// - Report export (JSON, HTML)
package main

import (
	"log"
	"os"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/securemailscope/backend/internal/db"
	"github.com/securemailscope/backend/internal/handler"
)

func main() {
	// Connect to PostgreSQL
	if err := db.Connect(); err != nil {
		log.Fatalf("Database connection failed: %v", err)
	}

	// Run migrations
	if err := db.Migrate(); err != nil {
		log.Fatalf("Database migration failed: %v", err)
	}

	// Create uploads directory
	os.MkdirAll("uploads", 0755)

	// Setup Gin router
	r := gin.Default()

	// CORS middleware — allow dashboard on :3000 and :5173
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:3000", "http://127.0.0.1:3000", "http://localhost:5173", "http://127.0.0.1:5173"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization"},
		ExposeHeaders:    []string{"Content-Length", "Content-Disposition"},
		AllowCredentials: true,
	}))

	// API routes
	api := r.Group("/api")
	{
		api.POST("/upload", handler.UploadPCAP)
		api.GET("/analyses", handler.GetAnalyses)
		api.GET("/analyses/:id", handler.GetAnalysis)
		api.GET("/analyses/:id/sessions", handler.GetAnalysisSessions)
		api.GET("/analyses/:id/report", handler.GetAnalysisReport)
		api.GET("/dashboard/summary", handler.GetDashboardSummary)
	}

	// Health check
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok", "service": "securemailscope-api"})
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("SecureMailScope API Server starting on :%s", port)
	if err := r.Run(":" + port); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
