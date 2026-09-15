"""
SecureMailScope — AI Risk Engine CLI

Main orchestrator that chains:
1. Feature engineering (JSON → numerical features)
2. Rule-based risk scoring (vulnerability detection)
3. Anomaly detection (Isolation Forest)
4. Remediation generation (config fix snippets)

Usage:
    python main.py --input sessions.json --output results.json
"""

import argparse
import json
import sys
from datetime import datetime, timezone

from feature_engineering import load_sessions, sessions_to_dataframe
from risk_scorer import score_sessions
from anomaly_detector import detect_anomalies
from remediation import generate_remediation


def main():
    parser = argparse.ArgumentParser(
        description="SecureMailScope AI Risk Engine — Analyze email TLS session metadata"
    )
    parser.add_argument(
        "--input", "-i",
        required=True,
        help="Path to JSON file from Go PCAP parser (sessions.json)",
    )
    parser.add_argument(
        "--output", "-o",
        default="results.json",
        help="Output path for analysis results (default: results.json)",
    )
    parser.add_argument(
        "--contamination", "-c",
        type=float,
        default=0.1,
        help="Anomaly detection contamination factor (default: 0.1)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output",
    )
    args = parser.parse_args()

    print("SecureMailScope AI Risk Engine v1.0")
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

    # ---- Step 2: Risk Scoring ----
    print("\n[2/4] Running rule-based vulnerability detection & risk scoring...")
    df = score_sessions(df)

    severity_counts = df["severity"].value_counts().to_dict()
    print(f"  → Risk distribution: {severity_counts}")

    avg_score = df["risk_score"].mean()
    print(f"  → Average risk score: {avg_score:.1f}/10")

    # ---- Step 3: Anomaly Detection ----
    print("\n[3/4] Running Isolation Forest anomaly detection...")
    df, anomaly_explanations = detect_anomalies(df, contamination=args.contamination)

    anomaly_count = df["is_anomalous"].sum()
    print(f"  → Detected {anomaly_count} anomalous session(s) out of {len(df)}")

    # ---- Step 4: Remediation Generation ----
    print("\n[4/4] Generating remediation recommendations...")
    all_remediations = []

    for _, row in df.iterrows():
        findings = row.get("findings", [])
        if findings:
            rems = generate_remediation(findings)
            all_remediations.append({
                "session_id": row.get("session_id", ""),
                "remediations": rems,
            })

    print(f"  → Generated recommendations for {len(all_remediations)} session(s)")

    # ---- Build Final Output ----
    results = build_results(df, anomaly_explanations, all_remediations, args.input)

    # Write output
    with open(args.output, "w") as f:
        json.dump(results, f, indent=2, default=str)

    print(f"\n{'=' * 50}")
    print(f"Results written to: {args.output}")
    print(f"\n=== Security Posture Summary ===")
    print(f"  Overall Score:    {results['summary']['overall_score']:.1f}/10 ({results['summary']['overall_severity']})")
    print(f"  Total Sessions:   {results['summary']['total_sessions']}")
    print(f"  Critical Issues:  {results['summary']['severity_breakdown'].get('CRITICAL', 0)}")
    print(f"  High Issues:      {results['summary']['severity_breakdown'].get('HIGH', 0)}")
    print(f"  Anomalies:        {results['summary']['anomaly_count']}")


def build_results(
    df, anomaly_explanations: list, all_remediations: list, input_file: str
) -> dict:
    """Build the final structured results JSON."""

    # Per-session results
    session_results = []
    remediation_map = {r["session_id"]: r["remediations"] for r in all_remediations}

    for _, row in df.iterrows():
        session_id = row.get("session_id", "")
        session_results.append({
            "session_id": session_id,
            "protocol": row.get("protocol", "Unknown"),
            "src_ip": row.get("src_ip", ""),
            "dst_ip": row.get("dst_ip", ""),
            "tls_version": row.get("tls_version", "Unknown"),
            "negotiated_cipher": row.get("negotiated_cipher", "None"),
            "has_forward_secrecy": bool(row.get("has_forward_secrecy", False)),
            "risk_score": float(row.get("risk_score", 1.0)),
            "severity": row.get("severity", "INFO"),
            "findings": row.get("findings", []),
            "anomaly_score": float(row.get("anomaly_score", 0.0)),
            "is_anomalous": bool(row.get("is_anomalous", False)),
            "remediations": remediation_map.get(session_id, []),
            # Feature scores for dashboard
            "scores": {
                "tls_version": float(row.get("tls_version_score", 0)),
                "cipher_strength": float(row.get("cipher_strength_score", 0)),
                "key_exchange": float(row.get("key_exchange_score", 0)),
                "certificate_key": float(row.get("cert_key_length_score", 0)),
                "signature_algorithm": float(row.get("cert_sig_algo_score", 0)),
            },
        })

    # Summary statistics
    severity_breakdown = df["severity"].value_counts().to_dict()
    tls_version_breakdown = df["tls_version"].value_counts().to_dict() if "tls_version" in df.columns else {}
    protocol_breakdown = df["protocol"].value_counts().to_dict() if "protocol" in df.columns else {}

    overall_score = df["risk_score"].mean() if len(df) > 0 else 1.0

    from risk_scorer import severity_label
    overall_severity = severity_label(overall_score)

    return {
        "analysis_metadata": {
            "engine_version": "1.0.0",
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
    """Write an empty results file when no sessions are found."""
    results = {
        "analysis_metadata": {
            "engine_version": "1.0.0",
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
            "total_sessions": 0,
        },
        "summary": {
            "overall_score": 1.0,
            "overall_severity": "INFO",
            "total_sessions": 0,
            "severity_breakdown": {},
            "tls_version_breakdown": {},
            "protocol_breakdown": {},
            "anomaly_count": 0,
        },
        "sessions": [],
        "anomaly_explanations": [],
    }
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2, default=str)


if __name__ == "__main__":
    main()
