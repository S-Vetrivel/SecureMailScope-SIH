"""
SecureMailScope — AI Risk Engine CLI v2.0

Chains:
1. Feature engineering (JSON → numerical features)
2. Anomaly detection (Isolation Forest)
3. AI Security Assessment Generation (per-session justification)
4. Remediation generation

Usage:
    python main.py --input sessions.json --output results.json
"""

import argparse
import json
import sys
import uuid
from datetime import datetime, timezone

from feature_engineering import load_sessions, sessions_to_dataframe
from anomaly_detector import detect_anomalies
from remediation import generate_remediation
from llm_integration import generate_llm_assessment, generate_global_assessment_stream


def generate_session_assessment(row: dict, is_anomalous: bool, anomaly_score: float) -> dict:
    """
    Generate a structured AI security assessment for a single session.
    Returns assessment with findings and AI justification text.
    """
    session_id = row.get("session_id", "")
    tls_version = row.get("tls_version", "None") or "None"
    cipher = row.get("negotiated_cipher", "None") or "None"
    has_fs = bool(row.get("has_forward_secrecy", 0))
    protocol = row.get("protocol", "Unknown")
    is_encrypted = bool(row.get("is_encrypted", 0))
    has_starttls = bool(row.get("has_starttls", 0))
    cert_key_bits = int(row.get("cert_key_bits", 0))
    cert_sig_algo = row.get("cert_sig_algo", "") or ""
    cert_expired = bool(row.get("cert_is_expired", 0))
    cert_weak_key = bool(row.get("cert_is_weak_key", 0))
    cert_weak_sig = bool(row.get("cert_is_weak_signature", 0))

    findings = list(row.get("findings", []) or [])
    assessment_parts = []

    # --- TLS Version Assessment ---
    if tls_version == "TLS 1.3":
        assessment_parts.append("TLS 1.3 in use — state-of-the-art encryption with forward secrecy by design.")
    elif tls_version == "TLS 1.2":
        assessment_parts.append("TLS 1.2 detected — acceptable but consider upgrading to TLS 1.3 for best-in-class security.")
        findings.append({
            "id": f"AI-TLS-INFO-{uuid.uuid4().hex[:6]}",
            "title": "TLS 1.2 — Upgrade Recommended",
            "severity": "INFO",
            "category": "TLS_VERSION",
            "session_id": session_id,
            "description": "This session uses TLS 1.2. While considered secure, TLS 1.3 eliminates legacy cipher suites, reduces handshake latency and provides stronger security guarantees.",
            "evidence": [f"Negotiated Version: {tls_version}", f"Cipher: {cipher}"],
            "recommendation": "Configure the email server to prefer TLS 1.3 (RFC 8446). TLS 1.2 should be kept only as a fallback for legacy client compatibility."
        })
    elif tls_version in ("TLS 1.1", "TLS 1.0", "SSLv3"):
        assessment_parts.append(f"CRITICAL: {tls_version} is deprecated and vulnerable to POODLE/BEAST attacks.")
        findings.append({
            "id": f"AI-TLS-CRIT-{uuid.uuid4().hex[:6]}",
            "title": f"Deprecated Protocol: {tls_version}",
            "severity": "CRITICAL" if tls_version == "SSLv3" else "HIGH",
            "category": "TLS_VERSION",
            "session_id": session_id,
            "description": f"{tls_version} is a deprecated and cryptographically broken protocol. It is vulnerable to known attacks including POODLE (CVE-2014-3566) and BEAST (CVE-2011-3389).",
            "evidence": [f"Negotiated Version: {tls_version}", "Protocol blacklisted by RFC 8996"],
            "recommendation": f"Immediately disable {tls_version} support on the server. Configure TLS_MIN_VERSION=TLS1.2 and preferably TLS1.3."
        })
    else:
        if not is_encrypted:
            assessment_parts.append("Session is UNENCRYPTED — email data transmitted as plaintext over the network.")
        else:
            assessment_parts.append("TLS version unknown — insufficient data from packet capture.")

    # --- Cipher Suite Assessment ---
    if cipher and cipher != "None":
        cipher_upper = cipher.upper()
        if "AES_256_GCM" in cipher_upper or "CHACHA20" in cipher_upper:
            assessment_parts.append(f"Cipher suite {cipher} is excellent — AEAD cipher providing authenticity and confidentiality.")
        elif "AES_128_GCM" in cipher_upper:
            assessment_parts.append(f"Cipher suite {cipher} is strong — AES-128-GCM with AEAD protection.")
        elif "AES_256_CBC" in cipher_upper or "AES_128_CBC" in cipher_upper:
            assessment_parts.append(f"Cipher suite {cipher} uses CBC mode — vulnerable to padding oracle attacks without proper MAC-then-Encrypt handling.")
            findings.append({
                "id": f"AI-CIPHER-MED-{uuid.uuid4().hex[:6]}",
                "title": "CBC Mode Cipher Suite — Potential Padding Oracle Risk",
                "severity": "MEDIUM",
                "category": "CIPHER_SUITE",
                "session_id": session_id,
                "description": "CBC mode cipher suites are susceptible to padding oracle attacks (Lucky13, BEAST) in TLS 1.2 and below. AEAD suites (GCM/ChaCha20) are strongly preferred.",
                "evidence": [f"Cipher: {cipher}", "CBC mode detected"],
                "recommendation": "Prefer AEAD cipher suites: TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256. Disable CBC mode suites on the server."
            })
        elif "RC4" in cipher_upper:
            assessment_parts.append(f"CRITICAL: RC4 cipher is broken and must be disabled immediately.")
            findings.append({
                "id": f"AI-CIPHER-CRIT-{uuid.uuid4().hex[:6]}",
                "title": "RC4 Cipher — Cryptographically Broken",
                "severity": "CRITICAL",
                "category": "CIPHER_SUITE",
                "session_id": session_id,
                "description": "RC4 is a broken stream cipher with numerous statistical biases that allow plaintext recovery. It has been officially prohibited by RFC 7465.",
                "evidence": [f"Cipher: {cipher}", "RC4 prohibited by RFC 7465"],
                "recommendation": "Immediately disable RC4 on all servers. Use TLS_AES_256_GCM_SHA384 or TLS_CHACHA20_POLY1305_SHA256."
            })
        elif "NULL" in cipher_upper:
            findings.append({
                "id": f"AI-CIPHER-CRIT-NULL-{uuid.uuid4().hex[:6]}",
                "title": "NULL Cipher — No Encryption",
                "severity": "CRITICAL",
                "category": "CIPHER_SUITE",
                "session_id": session_id,
                "description": "NULL cipher suites provide no encryption whatsoever. All data is transmitted in plaintext even within a TLS connection.",
                "evidence": [f"Cipher: {cipher}"],
                "recommendation": "Disable NULL cipher suites on the server. Enable only strong AEAD ciphers."
            })

    # --- Forward Secrecy Assessment ---
    if has_fs:
        assessment_parts.append("Perfect Forward Secrecy (PFS) is active — past sessions remain protected even if private key is compromised.")
    elif is_encrypted:
        assessment_parts.append("Forward Secrecy NOT detected — compromise of the server private key could expose past encrypted sessions.")
        findings.append({
            "id": f"AI-FS-HIGH-{uuid.uuid4().hex[:6]}",
            "title": "No Perfect Forward Secrecy",
            "severity": "HIGH",
            "category": "KEY_EXCHANGE",
            "session_id": session_id,
            "description": "This session does not use an ephemeral key exchange (ECDHE/DHE). If the server private key is ever compromised, an attacker with recorded traffic can decrypt all past sessions.",
            "evidence": ["Static key exchange detected (RSA key exchange)", f"Cipher: {cipher}"],
            "recommendation": "Configure the server to require ECDHE or DHE key exchange. In TLS 1.3, all cipher suites provide forward secrecy by default."
        })

    # --- Certificate Assessment ---
    if cert_expired:
        findings.append({
            "id": f"AI-CERT-EXP-{uuid.uuid4().hex[:6]}",
            "title": "Expired TLS Certificate",
            "severity": "CRITICAL",
            "category": "CERTIFICATE",
            "session_id": session_id,
            "description": "The server presented an expired TLS certificate. Clients may refuse connections or proceed unsafely by bypassing certificate validation.",
            "evidence": ["Certificate expiry date is in the past"],
            "recommendation": "Renew the TLS certificate immediately. Use Let's Encrypt with auto-renewal or a certificate management platform."
        })

    if cert_weak_key:
        findings.append({
            "id": f"AI-CERT-WEAK-{uuid.uuid4().hex[:6]}",
            "title": f"Weak Certificate Key ({cert_key_bits} bits)",
            "severity": "HIGH",
            "category": "CERTIFICATE",
            "session_id": session_id,
            "description": f"The certificate uses a {cert_key_bits}-bit key, which is below the NIST minimum of 2048 bits for RSA or 256 bits for ECDSA. Such keys can be factored using modern computing resources.",
            "evidence": [f"Key length: {cert_key_bits} bits", "NIST SP 800-57 minimum: RSA-2048 / ECDSA-256"],
            "recommendation": "Replace the certificate with RSA-4096 or ECDSA-256/384. ECDSA is preferred for performance at equivalent security levels."
        })

    if cert_weak_sig:
        findings.append({
            "id": f"AI-CERT-SIG-{uuid.uuid4().hex[:6]}",
            "title": f"Weak Certificate Signature Algorithm: {cert_sig_algo}",
            "severity": "HIGH",
            "category": "CERTIFICATE",
            "session_id": session_id,
            "description": f"The certificate is signed using {cert_sig_algo}, which is cryptographically weak. MD5 and SHA-1 signatures have known collision vulnerabilities.",
            "evidence": [f"Signature Algorithm: {cert_sig_algo}", "SHA-1 deprecated per CA/Browser Forum Baseline Requirements"],
            "recommendation": "Request a new certificate signed with SHA-256 or SHA-384. Most modern CAs issue SHA-256 by default."
        })

    # --- STARTTLS Assessment ---
    if has_starttls and not is_encrypted:
        assessment_parts.append("STARTTLS advertised but encryption not fully established — potential downgrade risk.")
    elif has_starttls and is_encrypted:
        assessment_parts.append("STARTTLS upgrade successful — plaintext email traffic successfully encrypted.")
    elif not has_starttls and not is_encrypted and protocol in ("SMTP", "IMAP", "POP3"):
        assessment_parts.append(f"UNENCRYPTED {protocol} session — credentials and email content exposed in plaintext.")

    # --- Anomaly Assessment ---
    if is_anomalous:
        assessment_parts.append(
            f"⚠️ Isolation Forest flagged this session as statistically anomalous "
            f"(score: {anomaly_score:.2f}). It deviates from the normal traffic baseline in one or more cryptographic parameters."
        )
        findings.append({
            "id": f"AI-ANOM-{uuid.uuid4().hex[:6]}",
            "title": "AI-Detected Statistical Anomaly",
            "severity": "MEDIUM",
            "category": "ANOMALY",
            "session_id": session_id,
            "description": f"The Isolation Forest model flagged this session as anomalous with a score of {anomaly_score:.2f}/1.0. The session's cryptographic parameters deviate significantly from the baseline distribution of this PCAP capture. This could indicate a misconfigured client, protocol downgrade attempt, or unusual negotiation behavior.",
            "evidence": [
                f"Anomaly score: {anomaly_score:.4f} (higher = more anomalous)",
                f"TLS Version: {tls_version}",
                f"Cipher: {cipher}",
                f"Forward Secrecy: {'Yes' if has_fs else 'No'}"
            ],
            "recommendation": "Investigate the session source. Verify the client is using approved email software with up-to-date TLS configuration. Consider network monitoring for repeated anomalous patterns."
        })
    else:
        if is_encrypted and tls_version in ("TLS 1.2", "TLS 1.3"):
            assessment_parts.append("Session passes Isolation Forest anomaly detection — cryptographic parameters are consistent with baseline traffic.")

    # Prepare evidence for Ollama LLM
    evidence = {
        "protocol": protocol,
        "tls_version": tls_version,
        "cipher": cipher,
        "forward_secrecy": has_fs,
        "is_encrypted": is_encrypted,
        "has_starttls": has_starttls,
        "cert_key_bits": cert_key_bits,
        "cert_sig_algo": cert_sig_algo,
        "cert_is_expired": cert_expired,
        "cert_is_weak_key": cert_weak_key,
        "is_anomalous": is_anomalous,
        "anomaly_score": anomaly_score,
        "existing_findings": [f["title"] for f in findings],
        "rule_engine_assessment": " ".join(assessment_parts)
    }

    # Ask the small AI agent for reasoning, correlation, and explanation
    llm_resp = generate_llm_assessment(evidence)
    ai_assessment = llm_resp.get("ai_assessment", " ".join(assessment_parts) if assessment_parts else "Session assessed \u2014 no significant cryptographic anomalies detected.")
    
    # We could also use llm_resp.get("root_cause") and llm_resp.get("remediation") here
    # and append them as a finding, or attach them to the assessment.
    if llm_resp.get("root_cause") and llm_resp.get("root_cause") != "N/A":
        ai_assessment += f"\n\nRoot Cause: {llm_resp.get('root_cause')}"
    if llm_resp.get("remediation") and llm_resp.get("remediation") != "N/A":
        ai_assessment += f"\nRemediation: {llm_resp.get('remediation')}"

    return {
        "findings": findings,
        "ai_assessment": ai_assessment,
    }


def main():
    parser = argparse.ArgumentParser(
        description="SecureMailScope AI Risk Engine v2.0 — Analyze email TLS session metadata"
    )
    parser.add_argument("--input", "-i", required=True, help="Path to JSON file from Go PCAP parser")
    parser.add_argument("--output", "-o", default="results.json", help="Output path for analysis results")
    parser.add_argument("--contamination", "-c", type=float, default=0.1, help="Anomaly contamination factor")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    args = parser.parse_args()

    print("SecureMailScope AI Risk Engine v2.0")
    print("=" * 50)

    # ---- Step 1: Load & Engineer Features ----
    print("\n[1/4] Loading sessions and extracting features...")
    try:
        sessions = load_sessions(args.input)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"ERROR: Failed to load input file: {e}", file=sys.stderr)
        sys.exit(1)

    if not sessions:
        print("WARNING: No sessions found in input file.", file=sys.stderr)
        write_empty_results(args.output)
        sys.exit(0)

    df = sessions_to_dataframe(sessions)
    print(f"  → Loaded {len(df)} sessions with {len(df.columns)} features")

    # Build a map from session_id → original Go session id (the full "analysis-xxx-Syyy" id)
    go_id_map = {}
    for sess in sessions:
        go_id = sess.get("id") or sess.get("session_id") or ""
        feature_sid = sess.get("session_id") or sess.get("id") or ""
        go_id_map[feature_sid] = go_id

    if "risk_score" in df.columns:
        avg_score = df["risk_score"].mean()
        print(f"  → Average risk score (from Go rule engine): {avg_score:.1f}/10")

    # ---- Step 2: Anomaly Detection ----
    print("\n[2/4] Running Isolation Forest anomaly detection...")
    df, anomaly_explanations = detect_anomalies(df, contamination=args.contamination)
    anomaly_count = df["is_anomalous"].sum()
    print(f"  → Detected {anomaly_count} anomalous session(s) out of {len(df)}")

    # ---- Step 3: AI Assessment Generation ----
    print("\n[3/4] Generating AI security assessments for all sessions...")
    session_assessments = []
    for _, row in df.iterrows():
        row_dict = row.to_dict()
        is_anomalous = bool(row.get("is_anomalous", False))
        anomaly_score = float(row.get("anomaly_score", 0.0))
        assessment = generate_session_assessment(row_dict, is_anomalous, anomaly_score)
        session_assessments.append(assessment)
    print(f"  → Generated assessments for {len(session_assessments)} sessions")

    # ---- Step 4: Remediation Generation ----
    print("\n[4/4] Generating remediation recommendations...")
    all_remediations = []
    for i, (_, row) in enumerate(df.iterrows()):
        findings = session_assessments[i]["findings"]
        if findings:
            rems = generate_remediation(findings)
            all_remediations.append({
                "session_id": row.get("session_id", ""),
                "remediations": rems,
            })
    print(f"  → Generated recommendations for {len(all_remediations)} session(s)")

    # ---- Step 5: Global AI Assessment Stream ----
    print("\n[5/5] Streaming global AI assessment to frontend...")
    # Gather evidence from all sessions
    all_evidence = []
    for i, (_, row) in enumerate(df.iterrows()):
        row_dict = row.to_dict()
        all_evidence.append({
            "session_id": row_dict.get("session_id", ""),
            "protocol": row_dict.get("protocol", "Unknown"),
            "risk_score": float(row_dict.get("risk_score", 1.0)),
            "findings": [f["title"] for f in session_assessments[i]["findings"]],
            "is_anomalous": bool(row_dict.get("is_anomalous", False))
        })
    
    global_ai_assessment = generate_global_assessment_stream(all_evidence)

    # ---- Build Final Output ----
    results = build_results(df, anomaly_explanations, all_remediations, session_assessments, go_id_map, args.input)
    results["global_ai_assessment"] = global_ai_assessment

    with open(args.output, "w") as f:
        json.dump(results, f, indent=2, default=str)

    print(f"\n{'=' * 50}")
    print(f"Results written to: {args.output}")
    print(f"\n=== Security Posture Summary ===")
    print(f"  Overall Score:    {results['summary']['overall_score']:.1f}/10 ({results['summary']['overall_severity']})")
    print(f"  Total Sessions:   {results['summary']['total_sessions']}")
    print(f"  Anomalies:        {results['summary']['anomaly_count']}")
    ai_findings_count = sum(len(a["findings"]) for a in session_assessments)
    print(f"  AI Findings:      {ai_findings_count}")


def build_results(df, anomaly_explanations, all_remediations, session_assessments, go_id_map, input_file):
    """Build the final structured results JSON."""
    session_results = []
    remediation_map = {r["session_id"]: r["remediations"] for r in all_remediations}

    for i, (_, row) in enumerate(df.iterrows()):
        session_id = row.get("session_id", "")
        go_id = go_id_map.get(session_id, session_id)
        assessment = session_assessments[i] if i < len(session_assessments) else {"findings": [], "ai_assessment": ""}

        session_results.append({
            "session_id": session_id,
            "go_session_id": go_id,   # The full Go session ID for backend matching
            "protocol": row.get("protocol", "Unknown"),
            "src_ip": row.get("src_ip", ""),
            "dst_ip": row.get("dst_ip", ""),
            "tls_version": row.get("tls_version", "Unknown"),
            "negotiated_cipher": row.get("negotiated_cipher", "None"),
            "has_forward_secrecy": bool(row.get("has_forward_secrecy", False)),
            "risk_score": float(row.get("risk_score", 1.0)),
            "severity": row.get("severity", "INFO"),
            "findings": assessment["findings"],
            "ai_assessment": assessment["ai_assessment"],
            "anomaly_score": float(row.get("anomaly_score", 0.0)),
            "is_anomalous": bool(row.get("is_anomalous", False)),
            "remediations": remediation_map.get(session_id, []),
            "scores": {
                "tls_version": float(row.get("tls_version_score", 0)),
                "cipher_strength": float(row.get("cipher_strength_score", 0)),
                "key_exchange": float(row.get("key_exchange_score", 0)),
                "certificate_key": float(row.get("cert_key_length_score", 0)),
                "signature_algorithm": float(row.get("cert_sig_algo_score", 0)),
            },
        })

    severity_breakdown = df["severity"].value_counts().to_dict() if "severity" in df.columns else {}
    tls_version_breakdown = df["tls_version"].value_counts().to_dict() if "tls_version" in df.columns else {}
    protocol_breakdown = df["protocol"].value_counts().to_dict() if "protocol" in df.columns else {}
    overall_score = df["risk_score"].mean() if len(df) > 0 else 1.0

    # Include AI findings in breakdown
    for assessment in session_assessments:
        for f in assessment["findings"]:
            sev = f.get("severity", "INFO")
            severity_breakdown[sev] = severity_breakdown.get(sev, 0) + 1

    overall_severity = "INFO"
    if overall_score >= 8.0:
        overall_severity = "CRITICAL"
    elif overall_score >= 6.0:
        overall_severity = "HIGH"
    elif overall_score >= 4.0:
        overall_severity = "MEDIUM"
    elif overall_score >= 2.0:
        overall_severity = "LOW"

    return {
        "analysis_metadata": {
            "engine_version": "2.0.0",
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
            "input_file": input_file,
            "total_sessions": len(df),
        },
        "summary": {
            "overall_score": round(overall_score, 1),
            "overall_severity": overall_severity,
            "total_sessions": len(df),
            "severity_breakdown": severity_breakdown,
            "tls_version_breakdown": tls_version_breakdown,
            "protocol_breakdown": protocol_breakdown,
            "anomaly_count": int(df["is_anomalous"].sum()) if "is_anomalous" in df.columns else 0,
            "forward_secrecy_percentage": round(
                (df["has_forward_secrecy"].mean() * 100) if "has_forward_secrecy" in df.columns else 0, 1
            ),
        },
        "sessions": session_results,
        "anomaly_explanations": anomaly_explanations,
    }


def write_empty_results(output_path: str):
    results = {
        "analysis_metadata": {"engine_version": "2.0.0", "analyzed_at": datetime.now(timezone.utc).isoformat(), "total_sessions": 0},
        "summary": {"overall_score": 1.0, "overall_severity": "INFO", "total_sessions": 0, "severity_breakdown": {}, "tls_version_breakdown": {}, "protocol_breakdown": {}, "anomaly_count": 0},
        "sessions": [],
        "anomaly_explanations": [],
    }
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2, default=str)


if __name__ == "__main__":
    main()
