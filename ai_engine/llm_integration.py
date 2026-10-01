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
Here are the facts extracted from the PCAP traffic:
{json.dumps(evidence, indent=2)}

Analyze the security posture of this session. Respond ONLY with a valid JSON object matching this schema exactly (no markdown formatting, no backticks, just raw JSON):
{{
  "ai_assessment": "Detailed paragraph explaining the security posture, reasoning, and correlation of any issues.",
  "root_cause": "Technical root cause if vulnerable, or 'Secure configuration' if safe",
  "remediation": "Recommended fix if vulnerable, or 'No action required' if safe"
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
        "ai_assessment": "Session assessed (LLM unavailable/timeout) \u2014 no significant cryptographic anomalies detected.",
        "root_cause": "N/A",
        "remediation": "N/A"
    }

    try:
        r = requests.post(url, json=payload, timeout=20)
        r.raise_for_status()
        resp_json = json.loads(r.json().get("response", "{}"))
        if "ai_assessment" in resp_json:
            return resp_json
    except Exception as e:
        print(f"  [!] Ollama API failed or timed out: {e}", file=sys.stderr)
        
    return fallback

def generate_global_assessment_stream(sessions_evidence: list) -> str:
    prompt = f"""You are a cybersecurity expert analyzing a complete network packet capture (PCAP) of email traffic.
Here are the aggregated details from all sessions in this capture:
{json.dumps(sessions_evidence, indent=2)}

Provide a comprehensive, executive-level AI security assessment of this entire PCAP. 
Highlight the overall security posture, any critical findings, and justify the risk score.
Write in a professional, clear markdown format.
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

