"""
SecureMailScope — Feature Engineering Module

Transforms raw JSON session metadata from the Go PCAP parser into numerical
feature vectors suitable for ML-based risk scoring and anomaly detection.
"""

import json
from typing import Any

import numpy as np
import pandas as pd


# ============================================================================
# TLS Version Scoring — higher = more secure
# ============================================================================
TLS_VERSION_SCORES = {
    "TLS 1.3": 1.0,
    "TLS 1.2": 0.8,
    "TLS 1.1": 0.3,
    "TLS 1.0": 0.1,
    "SSLv3": 0.0,
}

# ============================================================================
# Cipher Suite Strength Scoring
# Based on NIST SP 800-52r2 and known CVE vulnerabilities
# ============================================================================
CIPHER_STRENGTH_PATTERNS = {
    # Critically weak
    "NULL": 0.0,
    "RC4": 0.05,
    "DES_CBC": 0.1,
    "EXPORT": 0.0,
    # Weak
    "3DES": 0.2,
    "RC4_128": 0.1,
    # Moderate
    "AES_128_CBC": 0.5,
    "AES_256_CBC": 0.6,
    # Strong
    "AES_128_GCM": 0.85,
    "AES_256_GCM": 1.0,
    "CHACHA20_POLY1305": 1.0,
}

# ============================================================================
# Signature Algorithm Scoring
# ============================================================================
SIG_ALGO_SCORES = {
    "MD2-RSA": 0.0,
    "MD5-RSA": 0.0,
    "MD5WithRSA": 0.0,
    "SHA1-RSA": 0.2,
    "SHA1WithRSA": 0.2,
    "ECDSAWithSHA1": 0.2,
    "SHA256-RSA": 0.8,
    "SHA256WithRSA": 0.8,
    "SHA384-RSA": 0.9,
    "SHA384WithRSA": 0.9,
    "SHA512-RSA": 1.0,
    "SHA512WithRSA": 1.0,
    "ECDSAWithSHA256": 0.9,
    "ECDSAWithSHA384": 0.95,
    "ECDSAWithSHA512": 1.0,
    "Ed25519": 1.0,
}


def score_cipher_strength(cipher_name: str) -> float:
    """Score a cipher suite name based on the encryption algorithm strength."""
    if not cipher_name:
        return 0.0

    cipher_upper = cipher_name.upper()

    # Check patterns from weakest to strongest (return first match)
    for pattern, score in sorted(CIPHER_STRENGTH_PATTERNS.items(), key=lambda x: x[1]):
        if pattern in cipher_upper:
            # But check if there's a stronger match too
            pass

    # More specific matching
    if "NULL" in cipher_upper:
        return 0.0
    if "EXPORT" in cipher_upper:
        return 0.0
    if "RC4" in cipher_upper:
        return 0.05
    if "DES_CBC" in cipher_upper and "3DES" not in cipher_upper:
        return 0.1
    if "3DES" in cipher_upper:
        return 0.2
    if "CHACHA20" in cipher_upper:
        return 1.0
    if "AES_256_GCM" in cipher_upper or "AES256GCM" in cipher_upper:
        return 1.0
    if "AES_128_GCM" in cipher_upper or "AES128GCM" in cipher_upper:
        return 0.85
    if "AES_256_CBC" in cipher_upper or "AES256CBC" in cipher_upper:
        return 0.6
    if "AES_128_CBC" in cipher_upper or "AES128CBC" in cipher_upper:
        return 0.5
    if "AES" in cipher_upper:
        return 0.6  # Generic AES fallback

    return 0.3  # Unknown cipher — moderate risk


def score_key_length(bits: int) -> float:
    """Score RSA/key length — normalized 0.0 to 1.0."""
    if bits <= 0:
        return 0.5  # Unknown
    if bits <= 512:
        return 0.0
    if bits <= 768:
        return 0.1
    if bits <= 1024:
        return 0.3
    if bits <= 2048:
        return 0.7
    if bits <= 3072:
        return 0.85
    return 1.0  # 4096+


def score_signature_algorithm(algo: str) -> float:
    """Score signature algorithm strength."""
    if not algo:
        return 0.5

    # Try direct lookup
    for key, score in SIG_ALGO_SCORES.items():
        if key.lower() in algo.lower() or algo.lower() in key.lower():
            return score

    # Fallback heuristics
    algo_lower = algo.lower()
    if "md5" in algo_lower or "md2" in algo_lower:
        return 0.0
    if "sha1" in algo_lower:
        return 0.2
    if "sha256" in algo_lower:
        return 0.8
    if "sha384" in algo_lower:
        return 0.9
    if "sha512" in algo_lower:
        return 1.0

    return 0.5


def extract_session_features(session: dict[str, Any]) -> dict[str, Any]:
    """
    Extract numerical features from a single parsed email session.
    Supports both Go backend EmailSession JSON format and legacy parser format.

    Returns a flat dictionary of feature name -> float value.
    """
    session_id = session.get("session_id") or session.get("id") or ""
    protocol = session.get("protocol") or "Unknown"
    src_ip = session.get("src_ip") or (session.get("client") or {}).get("ip") or ""
    dst_ip = session.get("dst_ip") or (session.get("server") or {}).get("ip") or ""

    features: dict[str, Any] = {
        "session_id": session_id,
        "protocol": protocol,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
    }

    # ---- TLS Handshake Features ----
    hs = session.get("tls_handshake")
    tls = session.get("tls")

    neg_version = session.get("tls_version") or (tls.get("version") if tls else None) or (hs.get("negotiated_version") if hs else None) or "None"
    cipher = session.get("negotiated_cipher") or (tls.get("cipher_suite") if tls else None) or (hs.get("negotiated_cipher") if hs else None) or "None"
    
    fs_val = session.get("has_forward_secrecy")
    if fs_val is None:
        fs_val = session.get("forward_secrecy") == "YES" or (hs.get("has_forward_secrecy") if hs else False)

    features["tls_version"] = neg_version
    features["tls_version_score"] = TLS_VERSION_SCORES.get(neg_version, 0.0)
    features["negotiated_cipher"] = cipher
    features["cipher_strength_score"] = score_cipher_strength(cipher)
    features["has_forward_secrecy"] = 1.0 if fs_val else 0.0

    kex = (tls.get("key_exchange") if tls else None) or (hs.get("key_exchange") if hs else None) or "None"
    features["key_exchange"] = kex
    features["key_exchange_score"] = 1.0 if (kex in ("ECDHE", "DHE") or fs_val) else 0.3 if kex == "ECDH" else 0.0

    features["compression_enabled"] = 1.0 if hs and hs.get("compression_method", 0) != 0 else 0.0
    offered = (hs.get("cipher_suites_offered") if hs else None) or []
    features["num_cipher_suites_offered"] = len(offered)
    weak_count = sum(1 for c in (offered or []) if any(w in (c or "").upper() for w in ["NULL", "RC4", "DES", "EXPORT", "3DES"]))
    features["weak_ciphers_offered_count"] = weak_count
    features["weak_ciphers_offered_ratio"] = weak_count / max(len(offered), 1)

    # ---- Certificate Features ----
    certs = session.get("certificates", [])
    cert_obj = session.get("certificate") or (certs[0] if certs else None)
    if cert_obj:
        bits = cert_obj.get("public_key_bit_length") or cert_obj.get("key_bits") or 0
        sig_algo = cert_obj.get("signature_algorithm") or ""
        is_expired = cert_obj.get("is_expired") if "is_expired" in cert_obj else cert_obj.get("expired", False)
        is_self_signed = cert_obj.get("is_self_signed", False)

        features["cert_key_bits"] = bits
        features["cert_key_length_score"] = score_key_length(bits)
        features["cert_sig_algo"] = sig_algo
        features["cert_sig_algo_score"] = score_signature_algorithm(sig_algo)
        features["cert_is_self_signed"] = 1.0 if is_self_signed else 0.0
        features["cert_is_expired"] = 1.0 if is_expired else 0.0
        features["cert_is_weak_key"] = 1.0 if bits > 0 and bits < 2048 else 0.0
        features["cert_is_weak_signature"] = 1.0 if "md5" in sig_algo.lower() or "sha1" in sig_algo.lower() else 0.0

        not_after = cert_obj.get("not_after", "")
        if not_after:
            try:
                from datetime import datetime, timezone
                exp = datetime.fromisoformat(str(not_after).replace("Z", "+00:00"))
                days_left = (exp - datetime.now(timezone.utc)).days
                features["cert_days_until_expiry"] = days_left
            except (ValueError, TypeError):
                features["cert_days_until_expiry"] = 0
        else:
            features["cert_days_until_expiry"] = 0

        features["cert_chain_length"] = len(certs) if certs else 1
    else:
        features["cert_key_bits"] = 0
        features["cert_key_length_score"] = 0.0
        features["cert_sig_algo"] = "None"
        features["cert_sig_algo_score"] = 0.0
        features["cert_is_self_signed"] = 0.0
        features["cert_is_expired"] = 0.0
        features["cert_is_weak_key"] = 0.0
        features["cert_is_weak_signature"] = 0.0
        features["cert_days_until_expiry"] = 0
        features["cert_chain_length"] = 0

    # ---- Protocol Features ----
    starttls = session.get("starttls") or {}
    has_starttls = session.get("has_starttls") or starttls.get("supported", False) or starttls.get("tls_established", False)
    is_encrypted = session.get("is_encrypted") or (neg_version != "None" and neg_version != "")

    features["has_starttls"] = 1.0 if has_starttls else 0.0
    features["is_encrypted"] = 1.0 if is_encrypted else 0.0

    return features


# ============================================================================
# Numerical feature columns used for ML models
# ============================================================================
NUMERICAL_FEATURES = [
    "tls_version_score",
    "cipher_strength_score",
    "has_forward_secrecy",
    "key_exchange_score",
    "compression_enabled",
    "num_cipher_suites_offered",
    "weak_ciphers_offered_count",
    "weak_ciphers_offered_ratio",
    "cert_key_length_score",
    "cert_sig_algo_score",
    "cert_is_self_signed",
    "cert_is_expired",
    "cert_is_weak_key",
    "cert_is_weak_signature",
    "cert_days_until_expiry",
    "cert_chain_length",
    "has_starttls",
    "is_encrypted",
]


def load_sessions(json_path: str) -> list[dict]:
    """Load parsed sessions from the Go parser's JSON output."""
    with open(json_path, "r") as f:
        data = json.load(f)

    # Handle both direct list and wrapped format
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and "sessions" in data:
        return data["sessions"]

    return [data]


def sessions_to_dataframe(sessions: list[dict]) -> pd.DataFrame:
    """Convert a list of parsed sessions into a feature DataFrame."""
    feature_rows = []
    for session in sessions:
        features = extract_session_features(session)
        feature_rows.append(features)

    df = pd.DataFrame(feature_rows)

    # Ensure numerical columns are float
    for col in NUMERICAL_FEATURES:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0.0)

    return df


def get_feature_matrix(df: pd.DataFrame) -> np.ndarray:
    """Extract the numerical feature matrix from a DataFrame."""
    available_cols = [c for c in NUMERICAL_FEATURES if c in df.columns]
    return df[available_cols].values.astype(np.float64)
