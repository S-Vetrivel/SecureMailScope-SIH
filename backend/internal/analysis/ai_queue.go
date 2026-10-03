package analysis

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/securemailscope/backend/internal/models"
	"github.com/securemailscope/backend/internal/storage"
)

type AIQueue struct {
	router      *AIRouter
	repo        *storage.Repository
	jobQueue    chan *models.EmailSession
	workers     int
	broadcaster func(string)
}

func NewAIQueue(router *AIRouter, repo *storage.Repository, broadcaster func(string)) *AIQueue {
	workersStr := os.Getenv("AI_WORKERS")
	workers, err := strconv.Atoi(workersStr)
	if err != nil || workers <= 0 {
		workers = 2
	}
	
	queueSizeStr := os.Getenv("AI_QUEUE_SIZE")
	queueSize, err := strconv.Atoi(queueSizeStr)
	if err != nil || queueSize <= 0 {
		queueSize = 100
	}
	
	q := &AIQueue{
		router:      router,
		repo:        repo,
		jobQueue:    make(chan *models.EmailSession, queueSize),
		workers:     workers,
		broadcaster: broadcaster,
	}
	return q
}

func (q *AIQueue) Start() {
	for i := 0; i < q.workers; i++ {
		go q.worker(i)
	}
}

func (q *AIQueue) Enqueue(session *models.EmailSession) {
	select {
	case q.jobQueue <- session:
		// Enqueued
	default:
		// Queue full, discard AI processing to prevent blocking the forensic pipeline
		log.Printf("AI Queue full, dropping session %s from AI processing", session.ID)
	}
}

func (q *AIQueue) worker(id int) {
	for session := range q.jobQueue {
		q.processSession(session)
	}
}

func (q *AIQueue) processSession(session *models.EmailSession) {
	provider := q.router.GetActiveProvider()
	if provider == nil {
		log.Printf("No AI provider available for session %s, skipping AI assessment", session.ID)
		return
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	
	// Create evidence struct mapped from Python's evidence_json if it exists, or just pass the session
	evidence := session
	
	result, err := provider.GenerateStructuredAssessment(ctx, evidence)
	if err != nil {
		log.Printf("AI provider failed for session %s: %v", session.ID, err)
		return
	}
	
	// Ensure the result structure matches models.AIAssessmentResult
	mappedResult := &models.AIAssessmentResult{
		ExecutiveInterpretation: result.Summary + "\n" + result.SecurityInterpretation,
		AIReasoning:             result.RiskExplanation,
		Priority:                "INFO",
		RecommendedActions:      parseStringArray(result.RecommendedActions),
	}
	if result.Confidence > 0 {
		mappedResult.Priority = fmt.Sprintf("CONFIDENCE: %.2f", result.Confidence)
	}
	
	session.AIAssessmentStructured = mappedResult
	session.AIAssessment = result.Summary
	
	// Update database
	_ = q.repo.SaveSession(session)
	
	// Broadcast update via WebSocket
	if q.broadcaster != nil {
		q.broadcaster(fmt.Sprintf(`{"event": "ai_assessment_complete", "session_id": "%s"}`, session.ID))
	}
}
