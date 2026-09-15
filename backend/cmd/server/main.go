package main

import (
	"log"
	"net/http"
	"os"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/securemailscope/backend/internal/analysis"
	"github.com/securemailscope/backend/internal/api"
	"github.com/securemailscope/backend/internal/storage"
)

func main() {
	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "./data/securemailscope.db"
	}

	uploadDir := os.Getenv("UPLOAD_DIR")
	if uploadDir == "" {
		uploadDir = "./data/uploads"
	}

	port := os.Getenv("HTTP_PORT")
	if port == "" {
		port = "8080"
	}

	frontendOrigin := os.Getenv("FRONTEND_ORIGIN")
	if frontendOrigin == "" {
		frontendOrigin = "http://localhost:3000"
	}

	// Initialize Storage SQLite
	repo, err := storage.NewRepository(dbPath)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer repo.Close()

	// Initialize Analysis Service Pipeline
	tsharkPath := os.Getenv("TSHARK_PATH")
	if tsharkPath == "" {
		tsharkPath = "tshark"
	}
	analysisService := analysis.NewService(repo, tsharkPath)

	// Initialize API Server Handlers
	server := api.NewServer(repo, analysisService, uploadDir)

	router := gin.Default()

	// Configure CORS
	config := cors.DefaultConfig()
	config.AllowOrigins = []string{frontendOrigin, "http://localhost:5173", "http://127.0.0.1:5173"}
	config.AllowMethods = []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
	config.AllowHeaders = []string{"Origin", "Content-Type", "Accept", "Authorization"}
	router.Use(cors.New(config))

	server.RegisterRoutes(router)

	log.Printf("SecureMailScope Backend Server running on port :%s", port)
	if err := http.ListenAndServe(":"+port, router); err != nil {
		log.Fatalf("Server shutdown failed: %v", err)
	}
}
