package analysis

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"io"

	"github.com/google/uuid"
	"github.com/securemailscope/backend/internal/capture"
	"github.com/securemailscope/backend/internal/certificate"
	"github.com/securemailscope/backend/internal/models"
	"github.com/securemailscope/backend/internal/protocol"
	"github.com/securemailscope/backend/internal/risk"
	"github.com/securemailscope/backend/internal/session"
	"github.com/securemailscope/backend/internal/storage"
	"github.com/securemailscope/backend/internal/tlsinspect"
)

type ProgressEvent struct {
	AnalysisID string                `json:"analysis_id"`
	Stage      models.AnalysisStatus `json:"stage"`
	Progress   int                   `json:"progress"`
	Message    string                `json:"message"`
}

type Service struct {
	repo             *storage.Repository
	tsharkInspector  *tlsinspect.TSharkInspector
	riskEngine       *risk.Engine
	eventSubscribers []func(ProgressEvent)
	rawSubscribers   []func(string)
	
	aiRouter         *AIRouter
	aiQueue          *AIQueue
}

func NewService(repo *storage.Repository, tsharkPath string) *Service {
	s := &Service{
		repo:            repo,
		tsharkInspector: tlsinspect.NewTSharkInspector(tsharkPath, 60*time.Second),
		riskEngine:      risk.NewEngine(risk.DefaultPolicy()),
	}
	s.aiRouter = NewAIRouter()
	s.aiQueue = NewAIQueue(s.aiRouter, s.repo, s.broadcastRawWSEvent)
	s.aiQueue.Start()
	return s
}

func (s *Service) SubscribeEvents(fn func(ProgressEvent)) {
	s.eventSubscribers = append(s.eventSubscribers, fn)
}

func (s *Service) emitEvent(analysisID string, stage models.AnalysisStatus, progress int, msg string) {
	evt := ProgressEvent{
		AnalysisID: analysisID,
		Stage:      stage,
		Progress:   progress,
		Message:    msg,
	}
	for _, sub := range s.eventSubscribers {
		sub(evt)
	}
}

func (s *Service) SubscribeRawEvents(fn func(string)) {
	s.rawSubscribers = append(s.rawSubscribers, fn)
}

func (s *Service) broadcastRawWSEvent(msg string) {
	for _, sub := range s.rawSubscribers {
		sub(msg)
	}
}

func (s *Service) GetAIRouter() *AIRouter {
	return s.aiRouter
}

func (s *Service) CreateAnalysis(pcapPath string) (*models.Analysis, error) {
	id := fmt.Sprintf("analysis-%s", uuid.New().String()[:8])
	
	// Create forensic directory
	analysisDir := filepath.Join("/data", "analyses", id)
	if err := os.MkdirAll(analysisDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create analysis directory: %v", err)
	}

	destPcap := filepath.Join(analysisDir, "capture.pcap")
	if err := copyFile(pcapPath, destPcap); err != nil {
		return nil, fmt.Errorf("failed to preserve PCAP: %v", err)
	}

	analysis := &models.Analysis{
		ID:           id,
		PCAPPath:     destPcap,
		PCAPFilename: filepath.Base(pcapPath),
		Status:       models.StatusQueued,
		StartedAt:    time.Now(),
		SeverityBreakdown: make(map[string]int),
	}

	if err := s.repo.CreateAnalysis(analysis); err != nil {
		return nil, err
	}
	return analysis, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil { return err }
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil { return err }
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

func (s *Service) RunAnalysisAsync(id string) {
	go func() {
		if err := s.ExecutePipeline(id); err != nil {
			_ = s.repo.UpdateAnalysisStatus(id, models.StatusFailed, err.Error())
			s.emitEvent(id, models.StatusFailed, 100, fmt.Sprintf("Error: %v", err))
		}
	}()
}

func (s *Service) ExecutePipeline(id string) error {
	analysis, err := s.repo.GetAnalysis(id)
	if err != nil {
		return err
	}

	// Step 1: PARSING
	s.emitEvent(id, models.StatusParsing, 10, "Parsing PCAP packets")
	_ = s.repo.UpdateAnalysisStatus(id, models.StatusParsing, "")

	// Support seamless streams across chunk boundaries by merging with the previous chunk.
	// Only merge if the previous chunk is non-trivial (> 100 bytes).
	targetPCAP := analysis.PCAPPath
		if strings.Contains(analysis.PCAPFilename, "live-capture") {
			// Find the previous live capture chunk to merge. Since we moved the PCAPs to data/analyses,
			// we have to find the previous one in the DB or rely on the filename.
			// Actually, to make things robust and since we just copied the chunk, let's just use the chunk.
			// We can skip mergecap for this prototype to avoid breaking the forensic PCAP isolation,
			// or we merge it during live capture. For now, we will just use the targetPCAP directly.
		}

	reader := capture.NewPCAPReader(targetPCAP)
	reassembler := session.NewStreamReassembler()

	totalPackets, err := reader.ReadPackets(func(pkt capture.PacketMetadata) error {
		reassembler.ProcessPacket(pkt)
		return nil
	})
	if err != nil {
		return fmt.Errorf("packet reading failed: %w", err)
	}

	// Step 2: REASSEMBLING
	s.emitEvent(id, models.StatusReassembling, 30, "Reconstructing TCP streams")
	_ = s.repo.UpdateAnalysisStatus(id, models.StatusReassembling, "")

	streams := reassembler.GetStreams()
	_ = s.repo.UpdateAnalysisStats(id, totalPackets, len(streams))

	// Step 3: DETECTING PROTOCOLS & STARTTLS
	s.emitEvent(id, models.StatusDetectingProtocols, 50, "Identifying SMTP/IMAP/POP3 protocols")
	_ = s.repo.UpdateAnalysisStatus(id, models.StatusDetectingProtocols, "")

	detector := protocol.NewDetector()

	// PRE-ANALYSIS: Check if there's any actual email traffic before doing heavy extraction and AI risk processing.
	// Check both directions: client→server and server→client port assignments
	hasEmail := false
	for _, stream := range streams {
		// Try both port orderings — the reassembler may assign client/server differently
		det1 := detector.Detect(stream.ClientPort, stream.ServerPort, stream.FullPayload)
		det2 := detector.Detect(stream.ServerPort, stream.ClientPort, stream.FullPayload)
		if det1.Protocol == "SMTP" || det1.Protocol == "IMAP" || det1.Protocol == "POP3" ||
			det2.Protocol == "SMTP" || det2.Protocol == "IMAP" || det2.Protocol == "POP3" {
			hasEmail = true
			break
		}
	}

	if !hasEmail && strings.Contains(analysis.PCAPPath, "live-capture") {
		// Drop garbage live captures to keep the DB clean
		s.repo.DeleteAnalysis(id)
		os.Remove(analysis.PCAPPath)
		log.Printf("[ANALYSIS] %s: no email traffic found in %d streams, dropping", id, len(streams))
		return nil
	}
	timelineAnalyzer := protocol.NewTimelineAnalyzer()
	certParser := certificate.NewParser()

	// Step 4: Extract TLS using TShark (whole-file pass)
	s.emitEvent(id, models.StatusAnalyzingTLS, 70, "Inspecting TLS handshakes via TShark")
	_ = s.repo.UpdateAnalysisStatus(id, models.StatusAnalyzingTLS, "")

	// Map from tcp stream connection key → TLSInfo
	tlsByKey := make(map[session.ConnectionKey]models.TLSInfo)
	if s.tsharkInspector.Available() {
		tsharkTLS, _ := s.tsharkInspector.Inspect(targetPCAP)
		for _, t := range tsharkTLS {
			key := session.MakeConnectionKey(t.ClientIP, t.ClientPort, t.ServerIP, t.ServerPort)
			tlsByKey[key] = t
		}
	}

	// Step 5: PROCESS SESSIONS & RISK ASSESSMENT
	s.emitEvent(id, models.StatusAssessingRisk, 85, "Evaluating security findings")
	_ = s.repo.UpdateAnalysisStatus(id, models.StatusAssessingRisk, "")

	var totalRiskScore float64
	fsCount := 0
	severityBreakdown := make(map[string]int)
    var parsedSessions []models.EmailSession

	for idx, stream := range streams {
		var sessionID string
		if strings.Contains(analysis.PCAPPath, "live-capture") {
			sessionID = fmt.Sprintf("live-%s-%d-%s-%d-%d", stream.ClientIP, stream.ClientPort, stream.ServerIP, stream.ServerPort, stream.StartTime.Unix())
		} else {
			sessionID = fmt.Sprintf("%s-S%03d", id, idx+1)
		}
		det := detector.Detect(stream.ClientPort, stream.ServerPort, stream.FullPayload)
		events, starttlsInfo := timelineAnalyzer.Analyze(det.Protocol, stream)

		emailSession := models.EmailSession{
			ID:             sessionID,
			AnalysisID:     id,
			Client:         models.Endpoint{IP: stream.ClientIP, Port: stream.ClientPort},
			Server:         models.Endpoint{IP: stream.ServerIP, Port: stream.ServerPort},
			Protocol:       det.Protocol,
			StartTime:      stream.StartTime,
			EndTime:        stream.EndTime,
			PacketCount:    stream.PacketCount,
			ClientBytes:    stream.ClientBytes,
			ServerBytes:    stream.ServerBytes,
			StreamComplete: stream.StreamComplete,
			ReassemblyGap:  stream.ReassemblyGap,
			StartTLS:       starttlsInfo,
			ForwardSecrecy: models.FSUnknown,
			ProtocolEvents: events,
		}

		// Match TShark TLS data to this stream using ConnectionKey
		var tlsInfo *models.TLSInfo
		if t, ok := tlsByKey[stream.Key]; ok {
			tlsInfo = &t
		} else if len(tlsByKey) == 1 {
			// fallback if only 1 TLS stream in entire PCAP and somehow key mismatch
			for _, t := range tlsByKey {
				tCopy := t
				tlsInfo = &tCopy
				break
			}
		}

		if tlsInfo != nil {
			emailSession.TLS = tlsInfo
			emailSession.ForwardSecrecy = tlsinspect.AssessForwardSecrecy(tlsInfo.Version, tlsInfo.CipherSuite, tlsInfo.KeyExchangeGroup)
		} else if starttlsInfo.TLSEstablished {
			// TLS was established but TShark found no specific cipher — mark as incomplete
			emailSession.TLS = &models.TLSInfo{
				Version:            "",
				CipherSuite:        "",
				TLSObserved:        true,
			}
		}

		// Attempt certificate parsing from TShark raw output first, then raw payload
		if tlsInfo != nil && len(tlsInfo.RawCertificates) > 0 {
			if cert, err := certParser.ParseHexStrings(tlsInfo.RawCertificates); err == nil {
				emailSession.Certificate = cert
			}
		} else {
			if cert, err := certParser.ParseRawDER(stream.ServerPayload); err == nil {
				emailSession.Certificate = cert
			}
		}

		// Evaluate Risk Engine Findings
		findings := s.riskEngine.Assess(emailSession)
		emailSession.Findings = findings

		// Compute flat dashboard fields
		populateFlatFields(&emailSession)

		// Track aggregate stats
		totalRiskScore += emailSession.RiskScore
		if emailSession.HasForwardSecrecy {
			fsCount++
		}
		for _, f := range findings {
			severityBreakdown[string(f.Severity)]++
		}

		// Don't persist session just yet, wait for AI Engine results
		// _ = s.repo.SaveSession(&emailSession)
        
        // Save to slice for AI engine
        parsedSessions = append(parsedSessions, emailSession)
	}

    // Step 5.5: Run Python AI Engine
    s.emitEvent(id, models.StatusAssessingRisk, 90, "Running AI Anomaly Detection (Isolation Forest)")
    
    // Dump sessions to JSON
    analysisOutput := models.AnalysisOutput{
        AnalysisID: id,
        PcapFile: analysis.PCAPPath,
        ParsedAt: time.Now(),
        TotalPackets: totalPackets,
        TotalStreams: len(streams),
        Sessions: parsedSessions,
    }
    
    sessionsPath := filepath.Join(filepath.Dir(analysis.PCAPPath), "sessions.json")
    resultsPath := filepath.Join(filepath.Dir(analysis.PCAPPath), "ai_report.json")
    
    sessionsBytes, _ := json.Marshal(analysisOutput)
    _ = os.WriteFile(sessionsPath, sessionsBytes, 0644)
    
    // Run AI Engine
    cwd, _ := os.Getwd()
    aiEngineDir := filepath.Join(cwd, "..", "ai_engine")
    if _, err := os.Stat(aiEngineDir); err != nil {
        aiEngineDir = filepath.Join(cwd, "ai_engine") // depending on execution dir
    }
    pythonBin := filepath.Join(aiEngineDir, "venv", "bin", "python")
    aiScript := filepath.Join(aiEngineDir, "main.py")
    
    cmd := exec.Command(pythonBin, aiScript, "--input", sessionsPath, "--output", resultsPath)
    
    // Capture stdout for streaming AI events
    stdoutPipe, _ := cmd.StdoutPipe()
    if err := cmd.Start(); err != nil {
        s.emitEvent(id, models.StatusAssessingRisk, 95, fmt.Sprintf("AI Engine failed to start: %v", err))
    } else {
        // Read stdout line by line
        scanner := bufio.NewScanner(stdoutPipe)
        for scanner.Scan() {
            line := scanner.Text()
            if strings.HasPrefix(line, `{"event"`) {
                // Forward it directly to websocket
                s.broadcastRawWSEvent(line)
            } else {
                fmt.Println("[AI ENGINE]:", line)
            }
        }
        
        if err := cmd.Wait(); err != nil {
            s.emitEvent(id, models.StatusAssessingRisk, 95, fmt.Sprintf("AI Engine failed, falling back to rule engine"))
        } else {
            // Parse results.json
            resultsBytes, err := os.ReadFile(resultsPath)
            if err == nil {
            var aiResults struct {
                GlobalAIAssessment string `json:"global_ai_assessment"`
                Sessions []struct {
                    SessionID   string          `json:"session_id"`
                    GoSessionID string          `json:"go_session_id"`
                    IsAnomalous bool            `json:"is_anomalous"`
                    AnomalyScore float64        `json:"anomaly_score"`
                    Findings    []models.Finding `json:"findings"`
                    AIAssessment string          `json:"ai_assessment"`
                    AIAssessmentStructured *models.AIAssessmentResult `json:"ai_assessment_structured"`
                    Remediations []interface{}   `json:"remediations"`
                } `json:"sessions"`
            }
            if err := json.Unmarshal(resultsBytes, &aiResults); err == nil {
                // Save Global AI Assessment
                _ = s.repo.UpdateGlobalAIAssessment(id, aiResults.GlobalAIAssessment)

                // Merge AI results into sessions by Go session ID
                for i, sess := range parsedSessions {
                    for _, aiSess := range aiResults.Sessions {
                        // Match using the full Go session ID (go_session_id field)
                        // or fall back to suffix matching
                        goID := aiSess.GoSessionID
                        if goID == sess.ID || strings.HasSuffix(sess.ID, aiSess.SessionID) {
                            parsedSessions[i].IsAnomalous = aiSess.IsAnomalous
                            parsedSessions[i].AnomalyScore = aiSess.AnomalyScore
                            parsedSessions[i].AIAssessment = aiSess.AIAssessment
                            parsedSessions[i].AIAssessmentStructured = aiSess.AIAssessmentStructured
                            parsedSessions[i].Remediations = aiSess.Remediations
                            // Add AI findings
                            for _, f := range aiSess.Findings {
                                f.SessionID = sess.ID
                                if f.ID == "" {
                                    f.ID = "AI-" + uuid.New().String()[:8]
                                }
                                parsedSessions[i].Findings = append(parsedSessions[i].Findings, f)
                                severityBreakdown[string(f.Severity)]++
                            }
                            break
                        }
                    }
                }
            }
        }
    }
}
    
    // Recalculate max severity and save sessions
    totalRiskScore = 0
    severityBreakdown = make(map[string]int)
    for i, sess := range parsedSessions {
        maxScore := 0.0
        maxSev := "INFO"
        for _, f := range sess.Findings {
            sc := severityToScore(f.Severity)
            if sc > maxScore {
                maxScore = sc
                maxSev = string(f.Severity)
            }
            severityBreakdown[string(f.Severity)]++
        }
        parsedSessions[i].RiskScore = maxScore
        parsedSessions[i].Severity = maxSev
        totalRiskScore += maxScore
        
        _ = s.repo.SaveSession(&parsedSessions[i])
        
        // Enqueue session for AI assessment if active provider exists
        if s.aiRouter.GetActiveProvider() != nil {
            s.aiQueue.Enqueue(&parsedSessions[i])
        }
    }


	// Step 6: Update analysis aggregate stats
	sessionCount := len(streams)
	var overallScore float64
	var fsPct float64
	if sessionCount > 0 {
		overallScore = totalRiskScore / float64(sessionCount)
		fsPct = float64(fsCount) / float64(sessionCount) * 100
	}

	_ = s.repo.UpdateAnalysisAggregate(id, models.StatusCompleted, overallScore, fsPct, severityBreakdown)
	s.emitEvent(id, models.StatusCompleted, 100, fmt.Sprintf("Completed analysis of %s", filepath.Base(analysis.PCAPPath)))

    // Run Global AI Assessment asynchronously
    go func() {
        if s.aiRouter.GetActiveProvider() != nil {
            ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
            defer cancel()
            
            updatedAnalysis, _ := s.repo.GetAnalysis(id)
            if updatedAnalysis != nil {
                globalAssessment, err := s.aiRouter.GetActiveProvider().GenerateGlobalAssessment(ctx, updatedAnalysis, parsedSessions)
                if err == nil {
                    _ = s.repo.UpdateGlobalAIAssessment(id, globalAssessment)
                    s.broadcastRawWSEvent(fmt.Sprintf(`{"event": "global_ai_assessment_complete", "analysis_id": "%s"}`, id))
                } else {
                    log.Printf("Failed to generate global AI assessment for %s: %v", id, err)
                }
            }
        }
    }()

	return nil
}

// populateFlatFields fills dashboard-friendly flat fields from nested data
func populateFlatFields(s *models.EmailSession) {
	parts := strings.Split(s.ID, "-")
	if len(parts) > 0 {
		s.SessionID = parts[len(parts)-1]
	} else {
		s.SessionID = s.ID
	}
	s.SrcIP = s.Client.IP
	s.DstIP = s.Server.IP

	if s.TLS != nil {
		s.TLSVersion = s.TLS.Version
		s.NegotiatedCipher = s.TLS.CipherSuite
		s.SignatureAlgorithm = s.TLS.SignatureAlgorithm
	}

	s.HasForwardSecrecy = s.ForwardSecrecy == models.FSYes

	// Compute risk score and severity from findings
	maxScore := 0.0
	maxSev := "INFO"
	for _, f := range s.Findings {
		score := severityToScore(f.Severity)
		if score > maxScore {
			maxScore = score
			maxSev = string(f.Severity)
		}
	}
	s.RiskScore = maxScore
	s.Severity = maxSev

	// Compute Security Radar scores (0–1 scale, 1 = best)
	s.Scores = computeScores(s)
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

func computeScores(s *models.EmailSession) models.SessionScores {
	scores := models.SessionScores{}

	// TLS Version score: 1.0 = TLS 1.3, 0.8 = TLS 1.2, 0.4 = TLS 1.1, 0.1 = TLS 1.0, 0 = SSLv3/none
	if s.TLS != nil {
		switch s.TLS.Version {
		case "TLS 1.3":
			scores.TLSVersion = 1.0
		case "TLS 1.2":
			scores.TLSVersion = 0.8
		case "TLS 1.1":
			scores.TLSVersion = 0.4
		case "TLS 1.0":
			scores.TLSVersion = 0.2
		default:
			scores.TLSVersion = 0.0
		}

		// Cipher strength score
		cipher := strings.ToUpper(s.TLS.CipherSuite)
		switch {
		case strings.Contains(cipher, "AES_256_GCM") || strings.Contains(cipher, "CHACHA20"):
			scores.CipherStrength = 1.0
		case strings.Contains(cipher, "AES_128_GCM"):
			scores.CipherStrength = 0.9
		case strings.Contains(cipher, "AES_256_CBC"):
			scores.CipherStrength = 0.7
		case strings.Contains(cipher, "AES_128_CBC"):
			scores.CipherStrength = 0.6
		case strings.Contains(cipher, "3DES"):
			scores.CipherStrength = 0.2
		case strings.Contains(cipher, "RC4"):
			scores.CipherStrength = 0.1
		default:
			scores.CipherStrength = 0.5
		}

		// Key exchange (forward secrecy) score
		switch s.ForwardSecrecy {
		case models.FSYes:
			scores.KeyExchange = 1.0
		case models.FSNo:
			scores.KeyExchange = 0.2
		default:
			scores.KeyExchange = 0.5
		}
	}

	// Certificate score
	if s.Certificate != nil {
		certScore := 1.0
		if s.Certificate.Expired {
			certScore = math.Min(certScore, 0.1)
		}
		// Fix key bit size evaluation per key algorithm
		alg := strings.ToUpper(s.Certificate.KeyAlgorithm)
		bits := s.Certificate.KeyBits
		if bits > 0 {
			if alg == "RSA" && bits < 2048 {
				certScore = math.Min(certScore, 0.3)
			} else if alg == "ECDSA" && bits < 256 {
				certScore = math.Min(certScore, 0.3)
			}
		}
		scores.Certificate = certScore

		// Signature algorithm score
		sig := strings.ToUpper(s.Certificate.SignatureAlgorithm)
		switch {
		case strings.Contains(sig, "SHA256") || strings.Contains(sig, "SHA384") || strings.Contains(sig, "SHA512"):
			scores.SignatureAlgorithm = 1.0
		case strings.Contains(sig, "SHA1"):
			scores.SignatureAlgorithm = 0.3
		case strings.Contains(sig, "MD5"):
			scores.SignatureAlgorithm = 0.1
		default:
			scores.SignatureAlgorithm = 0.5
		}
	} else {
		scores.Certificate = 0.5
		scores.SignatureAlgorithm = 0.5
	}

	return scores
}
