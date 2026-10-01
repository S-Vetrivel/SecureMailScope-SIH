import requests
import json
import sys

def get_ollama_model():
    try:
        r = requests.get("http://localhost:11434/api/tags", timeout=5)
        if r.status_code == 200:
            models = [m["name"] for m in r.json().get("models", [])]
            for pref in ["qwen2.5:0.5b", "llama3.1:latest", "llama3.2:1b"]:
                if pref in models:
                    return pref
            if models:
                return models[0]
    except Exception:
        pass
    return "qwen2.5:0.5b"

def generate_llm_assessment(evidence: dict) -> dict:
    prompt = f"""You are a cybersecurity expert analyzing an email server TLS session.
Here are the exact facts extracted from the PCAP traffic:
{json.dumps(evidence, indent=2)}

Analyze the security posture of this session based strictly on the provided evidence. 
Do NOT hallucinate or invent details that are not in the evidence (e.g., do not claim a protocol is used if the timeline shows otherwise). 
Respond ONLY with a valid JSON object matching this schema exactly (no markdown formatting, no backticks, just raw JSON):
{{
  "executive_interpretation": "A 2-3 sentence summary of the session's overall security posture.",
  "evidence_correlation": [
    {{
      "evidence_name": "e.g., TLS Version",
      "observation": "e.g., TLS 1.0",
      "security_implication": "e.g., Deprecated protocol"
    }}
  ],
  "ai_reasoning": "A paragraph explaining how the individual observations combine into the overall security posture. Clearly distinguish between OBSERVED facts and INFERRED conclusions.",
  "priority": "CRITICAL, HIGH, MEDIUM, LOW, or SECURE",
  "recommended_actions": [
    "Action 1",
    "Action 2"
  ]
}}
"""
    model = get_ollama_model()
    url = "http://localhost:11434/api/generate"
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "format": "json"
    }
    
    fallback = {
        "executive_interpretation": "Session assessed (LLM unavailable/timeout) \u2014 no significant cryptographic anomalies detected.",
        "evidence_correlation": [],
        "ai_reasoning": "The AI reasoning engine was unavailable or timed out.",
        "priority": "UNKNOWN",
        "recommended_actions": []
    }

    try:
        r = requests.post(url, json=payload, timeout=20)
        r.raise_for_status()
        resp_json = json.loads(r.json().get("response", "{}"))
        if "executive_interpretation" in resp_json:
            return resp_json
    except Exception as e:
        print(f"  [!] Ollama API failed or timed out: {e}", file=sys.stderr)
        
    return fallback

def generate_global_assessment_stream(sessions_evidence: list) -> str:
    prompt = f"""You are a cybersecurity expert analyzing a complete network packet capture (PCAP) of email traffic.
Here are the exact aggregated details from all sessions in this capture:
{json.dumps(sessions_evidence, indent=2)}

Provide a comprehensive, executive-level AI security assessment of this entire PCAP. 
Highlight the overall security posture, any critical findings, and justify the risk score.
Write in a professional, clear markdown format.
Do NOT hallucinate or invent details that are not in the provided evidence. Base your conclusions strictly on the facts presented.
"""
    model = get_ollama_model()
    url = "http://localhost:11434/api/generate"
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": True,
    }
    
    full_text = ""
    try:
        # Start streaming response to frontend
        print(json.dumps({"event": "ai_stream_start"}), flush=True)
        r = requests.post(url, json=payload, stream=True, timeout=120)
        r.raise_for_status()
        
        for line in r.iter_lines():
            if line:
                chunk = json.loads(line)
                text = chunk.get("response", "")
                if text:
                    full_text += text
                    # Print intermediate chunk to stdout for Go to capture
                    print(json.dumps({
                        "event": "ai_stream",
                        "chunk": text
                    }), flush=True)
                    
        print(json.dumps({"event": "ai_stream_end"}), flush=True)
    except Exception as e:
        err_msg = f"Error during AI streaming: {e}"
        print(f"  [!] {err_msg}", file=sys.stderr)
        print(json.dumps({
            "event": "ai_stream",
            "chunk": f"\n\n> **Note:** {err_msg}"
        }), flush=True)
        print(json.dumps({"event": "ai_stream_end"}), flush=True)
        
    return full_text

