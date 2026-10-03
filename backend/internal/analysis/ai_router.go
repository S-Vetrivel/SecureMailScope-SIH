package analysis

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"
)

type AIProvider interface {
	Name() string
	HealthCheck(ctx context.Context) bool
	GenerateStructuredAssessment(ctx context.Context, evidence interface{}) (*OllamaAssessmentResult, error)
	GenerateGlobalAssessment(ctx context.Context, analysis interface{}, sessions interface{}) (string, error)
}

type OllamaAssessmentResult struct {
	Summary                string      `json:"summary"`
	SecurityInterpretation string      `json:"security_interpretation"`
	RiskExplanation        string      `json:"risk_explanation"`
	ObservedStrengths      interface{} `json:"observed_strengths"`
	ObservedWeaknesses     interface{} `json:"observed_weaknesses"`
	EvidenceInterpretation interface{} `json:"evidence_interpretation"`
	RecommendedActions     interface{} `json:"recommended_actions"`
	Confidence             float64     `json:"confidence"`
}

func parseStringArray(val interface{}) []string {
	if val == nil {
		return []string{}
	}
	switch v := val.(type) {
	case string:
		return []string{v}
	case []interface{}:
		var res []string
		for _, item := range v {
			if s, ok := item.(string); ok {
				res = append(res, s)
			}
		}
		return res
	default:
		// If it's an object or something else, stringify it
		b, _ := json.Marshal(v)
		return []string{string(b)}
	}
}

type OllamaProvider struct {
	name    string
	url     string
	model   string
	client  *http.Client
}

func NewOllamaProvider(name, url, model string, timeout time.Duration) *OllamaProvider {
	return &OllamaProvider{
		name:  name,
		url:   url,
		model: model,
		client: &http.Client{
			Timeout: timeout,
		},
	}
}

func (p *OllamaProvider) Name() string {
	return p.name
}

func (p *OllamaProvider) HealthCheck(ctx context.Context) bool {
	if p.url == "" {
		return false
	}
	req, err := http.NewRequestWithContext(ctx, "GET", p.url+"/api/tags", nil)
	if err != nil {
		return false
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func (p *OllamaProvider) GenerateStructuredAssessment(ctx context.Context, evidence interface{}) (*OllamaAssessmentResult, error) {
	prompt := fmt.Sprintf(`You are a cybersecurity expert analyzing an email server TLS session.
Here are the exact facts extracted from the PCAP traffic:
%s

Analyze the security posture of this session based strictly on the provided evidence.
- Never invent packet observations.
- Never invent TLS versions.
- Never invent cipher suites.
- Never invent certificates.
- Never invent vulnerabilities.
- Never claim an attack occurred unless evidence explicitly supports it.
- Never claim a high risk score if the numerical score is 0.
- Do not describe symmetric encryption of messages unless application data is actually observed. Focus only on the cryptographic negotiation (e.g., TLS version, selected cipher, key exchange) based on the observed handshakes.
- Distinguish observed facts from interpretation.
- If evidence is missing, say "Not observed" or "Insufficient evidence".
- Do not replace deterministic findings.
- Do not modify numerical forensic evidence.

Respond ONLY with a valid JSON object matching this schema exactly (no markdown formatting, no backticks, just raw JSON):
{
  "summary": "...",
  "security_interpretation": "...",
  "risk_explanation": "...",
  "observed_strengths": [],
  "observed_weaknesses": [],
  "evidence_interpretation": [],
  "recommended_actions": [],
  "confidence": 0.0
}`, marshalEvidence(evidence))

	reqBody, _ := json.Marshal(map[string]interface{}{
		"model":  p.model,
		"prompt": prompt,
		"stream": false,
		"format": "json",
	})

	req, err := http.NewRequestWithContext(ctx, "POST", p.url+"/api/generate", bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Ollama returned status: %d", resp.StatusCode)
	}

	var ollamaResp struct {
		Response string `json:"response"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&ollamaResp); err != nil {
		return nil, err
	}

	var result OllamaAssessmentResult
	if err := json.Unmarshal([]byte(ollamaResp.Response), &result); err != nil {
		return nil, err
	}

	return &result, nil
}

func marshalEvidence(evidence interface{}) string {
	b, _ := json.MarshalIndent(evidence, "", "  ")
	return string(b)
}

func (p *OllamaProvider) GenerateGlobalAssessment(ctx context.Context, analysis interface{}, sessions interface{}) (string, error) {
	prompt := fmt.Sprintf(`You are a cybersecurity expert summarizing a network forensic analysis of an email server.
Here are the overall analysis stats:
%s

Here are the individual sessions analyzed:
%s

Provide a comprehensive, executive-level summary of the overall security posture, key risks, and strategic recommendations.
- Be objective and factual.
- If there are critical vulnerabilities, highlight them.
- If the risk score is 0, explicitly state that no vulnerabilities or anomalies were found, and DO NOT claim there is high risk.
- Do not make unsupported claims about the server being secure or compromised; restrict your claims to the evidence provided.
- Do not describe symmetric encryption of messages unless application data is actually observed. Focus only on the cryptographic negotiation.
- Format the response as a single, well-structured text summary (Markdown is acceptable).
- Do not output JSON.`, marshalEvidence(analysis), marshalEvidence(sessions))

	reqBody, _ := json.Marshal(map[string]interface{}{
		"model":  p.model,
		"prompt": prompt,
		"stream": false,
	})

	req, err := http.NewRequestWithContext(ctx, "POST", p.url+"/api/generate", bytes.NewBuffer(reqBody))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Ollama returned status: %d", resp.StatusCode)
	}

	var ollamaResp struct {
		Response string `json:"response"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&ollamaResp); err != nil {
		return "", err
	}

	return ollamaResp.Response, nil
}

type AIRouter struct {
	remoteProvider *OllamaProvider
	localProvider  *OllamaProvider
	mu             sync.RWMutex
	
	activeProviderName string
	remoteHealthy      bool
	localHealthy       bool
	remoteLatencyMs    int64
	localLatencyMs     int64
	
	remoteEnabled bool
	localEnabled  bool
}

func NewAIRouter() *AIRouter {
	remoteEnabled := os.Getenv("AI_REMOTE_ENABLED") == "true"
	localEnabled := os.Getenv("AI_LOCAL_ENABLED") == "true"
	
	parseTimeout := func(envKey string, defaultSecs int) time.Duration {
		val := os.Getenv(envKey)
		if val == "" {
			return time.Duration(defaultSecs) * time.Second
		}
		ms, err := strconv.Atoi(val)
		if err != nil || ms <= 0 {
			return time.Duration(defaultSecs) * time.Second
		}
		return time.Duration(ms) * time.Millisecond
	}

	var remote *OllamaProvider
	if remoteEnabled {
		remoteTimeout := parseTimeout("AI_REMOTE_TIMEOUT_MS", 60)
		remote = NewOllamaProvider("remote", os.Getenv("AI_REMOTE_URL"), os.Getenv("AI_REMOTE_MODEL"), remoteTimeout)
	}
	
	var local *OllamaProvider
	if localEnabled {
		localTimeout := parseTimeout("AI_LOCAL_TIMEOUT_MS", 60)
		local = NewOllamaProvider("local", os.Getenv("AI_LOCAL_URL"), os.Getenv("AI_LOCAL_MODEL"), localTimeout)
	}
	
	r := &AIRouter{
		remoteProvider: remote,
		localProvider:  local,
		remoteEnabled:  remoteEnabled,
		localEnabled:   localEnabled,
	}
	
	go r.healthCheckLoop()
	return r
}

func (r *AIRouter) healthCheckLoop() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	
	// Initial check
	r.checkHealth()
	
	for range ticker.C {
		r.checkHealth()
	}
}

func (r *AIRouter) checkHealth() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	r.mu.Lock()
	defer r.mu.Unlock()
	
	if r.remoteEnabled && r.remoteProvider != nil {
		start := time.Now()
		r.remoteHealthy = r.remoteProvider.HealthCheck(ctx)
		r.remoteLatencyMs = time.Since(start).Milliseconds()
	}
	
	if r.localEnabled && r.localProvider != nil {
		start := time.Now()
		r.localHealthy = r.localProvider.HealthCheck(ctx)
		r.localLatencyMs = time.Since(start).Milliseconds()
	}
	
	if r.remoteEnabled && r.remoteHealthy {
		r.activeProviderName = "remote"
	} else if r.localEnabled && r.localHealthy {
		r.activeProviderName = "local"
	} else {
		r.activeProviderName = "none"
	}
}

func (r *AIRouter) GetActiveProvider() AIProvider {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	if r.activeProviderName == "remote" {
		return r.remoteProvider
	} else if r.activeProviderName == "local" {
		return r.localProvider
	}
	return nil
}

type AIStatus struct {
	ActiveProvider string `json:"active_provider"`
	Remote         struct {
		Enabled   bool   `json:"enabled"`
		Healthy   bool   `json:"healthy"`
		Model     string `json:"model"`
		LatencyMs int64  `json:"latency_ms"`
	} `json:"remote"`
	Local struct {
		Enabled   bool   `json:"enabled"`
		Healthy   bool   `json:"healthy"`
		Model     string `json:"model"`
		LatencyMs int64  `json:"latency_ms"`
	} `json:"local"`
	FallbackActive bool `json:"fallback_active"`
}

func (r *AIRouter) GetStatus() AIStatus {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	var status AIStatus
	status.ActiveProvider = r.activeProviderName
	if r.remoteProvider != nil {
		status.Remote.Enabled = r.remoteEnabled
		status.Remote.Healthy = r.remoteHealthy
		status.Remote.Model = r.remoteProvider.model
		status.Remote.LatencyMs = r.remoteLatencyMs
	}
	if r.localProvider != nil {
		status.Local.Enabled = r.localEnabled
		status.Local.Healthy = r.localHealthy
		status.Local.Model = r.localProvider.model
		status.Local.LatencyMs = r.localLatencyMs
	}
	
	status.FallbackActive = r.activeProviderName == "local" && r.remoteEnabled && !r.remoteHealthy
	return status
}
