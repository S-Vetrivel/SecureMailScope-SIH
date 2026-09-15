package analysis

import (
	"fmt"
	"math"
	"path/filepath"
	"strings"
	"time"

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
}

func NewService(repo *storage.Repository, tsharkPath string) *Service {
	return &Service{
		repo:            repo,
		tsharkInspector: tlsinspect.NewTSharkInspector(tsharkPath, 60*time.Second),
		riskEngine:      risk.NewEngine(risk.DefaultPolicy()),
	}
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

func (s *Service) CreateAnalysis(pcapPath string) (*models.Analysis, error) {
	id := fmt.Sprintf("analysis-%s", uuid.New().String()[:8])
	analysis := &models.Analysis{
		ID:           id,
		PCAPPath:     pcapPath,
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

	reader := capture.NewPCAPReader(analysis.PCAPPath)
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
	starttlsAnalyzer := protocol.NewStartTLSAnalyzer()
	certParser := certificate.NewParser()

	// Step 4: Extract TLS using TShark (whole-file pass)
	s.emitEvent(id, models.StatusAnalyzingTLS, 70, "Inspecting TLS handshakes via TShark")
	_ = s.repo.UpdateAnalysisStatus(id, models.StatusAnalyzingTLS, "")

	// Map from tcp stream index → TLSInfo
	tlsByStream := make(map[int]models.TLSInfo)
	if s.tsharkInspector.Available() {
		tsharkTLS, _ := s.tsharkInspector.Inspect(analysis.PCAPPath)
		for _, t := range tsharkTLS {
			tlsByStream[t.StreamID] = t
		}
	}

	// Step 5: PROCESS SESSIONS & RISK ASSESSMENT
	s.emitEvent(id, models.StatusAssessingRisk, 85, "Evaluating security findings")
	_ = s.repo.UpdateAnalysisStatus(id, models.StatusAssessingRisk, "")

	var totalRiskScore float64
	fsCount := 0
	severityBreakdown := make(map[string]int)

	for idx, stream := range streams {
		sessionID := fmt.Sprintf("%s-S%03d", id, idx+1)
		det := detector.Detect(stream.ClientPort, stream.ServerPort, stream.FullPayload)
		starttlsInfo := starttlsAnalyzer.Analyze(det.Protocol, stream.ClientPayload, stream.ServerPayload)

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
		}

		// Match TShark TLS data to this stream (try stream index, then stream ID 0 for single-stream PCAPs)
		var tlsInfo *models.TLSInfo
		if t, ok := tlsByStream[idx]; ok {
			tlsInfo = &t
		} else if t, ok := tlsByStream[0]; ok && len(tlsByStream) == 1 {
			tlsInfo = &t
		}

		if tlsInfo != nil {
			emailSession.TLS = tlsInfo
			emailSession.ForwardSecrecy = tlsinspect.AssessForwardSecrecy(tlsInfo.Version, tlsInfo.CipherSuite)
		} else if starttlsInfo.TLSEstablished {
			// TLS was established but TShark found no specific cipher — mark as incomplete
			emailSession.TLS = &models.TLSInfo{
				Version:            "",
				CipherSuite:        "",
				HandshakeSucceeded: true,
				Complete:           false,
			}
		}

		// Attempt certificate parsing from raw payload
		if cert, err := certParser.ParseRawDER(stream.ServerPayload); err == nil {
			emailSession.Certificate = cert
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

		// Persist session
		_ = s.repo.SaveSession(&emailSession)
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
