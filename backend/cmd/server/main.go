package main

import (
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"github.com/securemailscope/backend/internal/analysis"
	"github.com/securemailscope/backend/internal/api"
	"github.com/securemailscope/backend/internal/storage"
)

func main() {
	if err := godotenv.Load("../.env"); err != nil {
		_ = godotenv.Load("../.env.example")
	}
	
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
		port = "6000"
	}

	frontendOrigin := os.Getenv("FRONTEND_ORIGIN")
	if frontendOrigin == "" {
		frontendOrigin = "http://localhost:3000"
	}

	frontendDir := os.Getenv("FRONTEND_DIR")
	if frontendDir == "" {
		frontendDir = "../dashboard/dist"
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

	// Custom CORS Middleware to guarantee no CORS errors and add logging
	router.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, PATCH, DELETE")

		if c.Request.Method == "OPTIONS" {
			log.Printf("[CORS] Preflight request allowed for %s", c.Request.URL.Path)
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	})

	server.RegisterRoutes(router)

	// Serve React Frontend
	router.Static("/assets", filepath.Join(frontendDir, "assets"))
	router.NoRoute(func(c *gin.Context) {
		c.File(filepath.Join(frontendDir, "index.html"))
	})

	log.Printf("SecureMailScope Backend Server running on port :%s", port)
	if err := http.ListenAndServe(":"+port, router); err != nil {
		log.Fatalf("Server shutdown failed: %v", err)
	}
}
