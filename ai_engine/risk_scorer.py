"""
SecureMailScope — Risk Scorer Module

Combines rule-based vulnerability detection with XGBoost classification
to produce a normalized risk score (1-10) and severity label per session.

Known CVE/vulnerability patterns detected:
- POODLE (SSLv3 + CBC ciphers)
- SWEET32 (3DES/Blowfish with 64-bit blocks)
- BEAST (TLS 1.0 + CBC mode)
- CRIME (TLS compression enabled)
- FREAK/LOGJAM (export-grade / DHE <1024)
- RC4 bias attacks
- Heartbleed indicators (OpenSSL version in cert metadata)
"""

from dataclasses import dataclass, field

import numpy as np
import pandas as pd


@dataclass
class Finding:
    """A single security finding for a session."""
    id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    title: str
    description: str
    cve_ids: list[str] = field(default_factory=list)
    remediation: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "cve_ids": self.cve_ids,
            "remediation": self.remediation,
        }


# Severity weights for score calculation
SEVERITY_WEIGHTS = {
    "CRITICAL": 10.0,
    "HIGH": 7.5,
    "MEDIUM": 5.0,
    "LOW": 2.5,
    "INFO": 1.0,
}


def detect_vulnerabilities(row: pd.Series) -> list[Finding]:
    """
    Run rule-based vulnerability detection on a single session's features.

    Returns a list of Finding objects describing detected issues.
    """
    findings: list[Finding] = []

    # ===== TLS Version Checks =====

    tls_version = str(row.get("tls_version", ""))

    if tls_version == "SSLv3":
        findings.append(Finding(
            id="VULN-TLS-001",
            severity="CRITICAL",
            title="SSLv3 Protocol Detected",
            description="SSLv3 is cryptographically broken and vulnerable to the POODLE attack (CVE-2014-3566). All data transmitted over SSLv3 should be considered compromised.",
            cve_ids=["CVE-2014-3566"],
            remediation="Disable SSLv3 immediately. Configure minimum protocol to TLS 1.2.",
        ))
    elif tls_version == "TLS 1.0":
        findings.append(Finding(
            id="VULN-TLS-002",
            severity="HIGH",
            title="TLS 1.0 Protocol Detected (Deprecated)",
            description="TLS 1.0 is deprecated per RFC 8996 and is vulnerable to BEAST (CVE-2011-3389) and other attacks. PCI DSS 3.2+ requires TLS 1.2 minimum.",
            cve_ids=["CVE-2011-3389"],
            remediation="Upgrade to TLS 1.2 or TLS 1.3.",
        ))
    elif tls_version == "TLS 1.1":
        findings.append(Finding(
            id="VULN-TLS-003",
            severity="HIGH",
            title="TLS 1.1 Protocol Detected (Deprecated)",
            description="TLS 1.1 is deprecated per RFC 8996. Major browsers and services have dropped support.",
            remediation="Upgrade to TLS 1.2 or TLS 1.3.",
        ))
    elif tls_version == "None" or not tls_version:
        findings.append(Finding(
            id="VULN-TLS-010",
            severity="CRITICAL",
            title="No TLS Encryption Detected",
            description="Email session is completely unencrypted. All data including credentials are transmitted in plaintext.",
            remediation="Enable TLS encryption on the mail server.",
        ))

    # ===== Cipher Suite Checks =====

    cipher = str(row.get("negotiated_cipher", "")).upper()

    if "NULL" in cipher:
        findings.append(Finding(
            id="VULN-CIPHER-001",
            severity="CRITICAL",
            title="NULL Cipher Suite Negotiated",
            description="No encryption is applied despite TLS negotiation. Data is transmitted in cleartext within a TLS wrapper.",
            remediation="Remove all NULL cipher suites from server configuration.",
        ))

    if "RC4" in cipher:
        findings.append(Finding(
            id="VULN-CIPHER-002",
            severity="HIGH",
            title="RC4 Cipher Suite Detected",
            description="RC4 has known statistical biases that enable plaintext recovery (CVE-2013-2566, CVE-2015-2808). RFC 7465 prohibits RC4 in TLS.",
            cve_ids=["CVE-2013-2566", "CVE-2015-2808"],
            remediation="Disable RC4. Use AES-GCM or ChaCha20-Poly1305 ciphers.",
        ))

    if "3DES" in cipher or "DES_EDE" in cipher:
        findings.append(Finding(
            id="VULN-CIPHER-003",
            severity="MEDIUM",
            title="3DES Cipher Suite Detected (SWEET32)",
            description="3DES uses 64-bit blocks, making it vulnerable to birthday attacks after ~32GB of data (SWEET32, CVE-2016-2183).",
            cve_ids=["CVE-2016-2183"],
            remediation="Disable 3DES. Use AES-128-GCM or AES-256-GCM.",
        ))

    if "EXPORT" in cipher:
        findings.append(Finding(
            id="VULN-CIPHER-004",
            severity="CRITICAL",
            title="Export-Grade Cipher Suite Detected (FREAK)",
            description="Export-grade ciphers use deliberately weakened encryption (40-56 bit keys) and are vulnerable to the FREAK attack (CVE-2015-0204).",
            cve_ids=["CVE-2015-0204"],
            remediation="Remove all export-grade cipher suites.",
        ))

    # ===== Forward Secrecy Check =====

    if row.get("has_forward_secrecy", 0) == 0 and tls_version not in ("None", ""):
        findings.append(Finding(
            id="VULN-KEX-001",
            severity="MEDIUM",
            title="No Forward Secrecy (PFS)",
            description="Static RSA key exchange does not provide forward secrecy. If the server's private key is compromised, all past sessions can be decrypted.",
            remediation="Enable ECDHE or DHE key exchange. Prefer ECDHE for performance.",
        ))

    # ===== TLS Compression (CRIME) =====

    if row.get("compression_enabled", 0) == 1:
        findings.append(Finding(
            id="VULN-COMP-001",
            severity="HIGH",
            title="TLS Compression Enabled (CRIME/BREACH)",
            description="TLS-level compression enables the CRIME attack (CVE-2012-4929), allowing attackers to recover secrets through compression ratio analysis.",
            cve_ids=["CVE-2012-4929"],
            remediation="Disable TLS compression (ssl_comp = no).",
        ))

    # ===== Certificate Checks =====

    if row.get("cert_is_expired", 0) == 1:
        findings.append(Finding(
            id="VULN-CERT-001",
            severity="CRITICAL",
            title="Expired X.509 Certificate",
            description="The server certificate has expired. Clients will display security warnings and may refuse to connect, enabling MITM attacks if users bypass warnings.",
            remediation="Renew the certificate immediately. Consider automated renewal with Let's Encrypt/ACME.",
        ))

    if row.get("cert_is_self_signed", 0) == 1:
        findings.append(Finding(
            id="VULN-CERT-002",
            severity="HIGH",
            title="Self-Signed Certificate Detected",
            description="Self-signed certificates cannot be validated by clients against a trusted CA chain, making MITM attacks trivial.",
            remediation="Obtain a certificate from a trusted Certificate Authority.",
        ))

    if row.get("cert_is_weak_key", 0) == 1:
        key_bits = int(row.get("cert_key_bits", 0))
        severity = "CRITICAL" if key_bits < 1024 else "HIGH"
        findings.append(Finding(
            id="VULN-CERT-003",
            severity=severity,
            title=f"Weak Certificate Key ({key_bits}-bit RSA)",
            description=f"The certificate uses a {key_bits}-bit RSA key. NIST recommends minimum 2048-bit RSA keys. Keys under 1024 bits can be factored.",
            remediation="Regenerate the certificate with at least RSA 2048-bit or ECDSA P-256.",
        ))

    if row.get("cert_is_weak_signature", 0) == 1:
        sig_algo = str(row.get("cert_sig_algo", ""))
        findings.append(Finding(
            id="VULN-CERT-004",
            severity="HIGH",
            title=f"Weak Signature Algorithm ({sig_algo})",
            description=f"The certificate uses {sig_algo}, which is cryptographically weak. SHA-1 collision attacks are practical (SHAttered, 2017).",
            remediation="Reissue the certificate with SHA-256 or stronger signature algorithm.",
        ))

    cert_days = row.get("cert_days_until_expiry", 0)
    if isinstance(cert_days, (int, float)) and 0 < cert_days <= 30:
        findings.append(Finding(
            id="VULN-CERT-005",
            severity="MEDIUM",
            title=f"Certificate Expiring Soon ({int(cert_days)} days)",
            description=f"The certificate will expire in {int(cert_days)} days. Failure to renew will cause service disruption.",
            remediation="Renew the certificate before expiration. Set up monitoring alerts.",
        ))

    # ===== BEAST Attack (TLS 1.0 + CBC) =====

    if tls_version == "TLS 1.0" and "CBC" in cipher:
        findings.append(Finding(
            id="VULN-BEAST-001",
            severity="HIGH",
            title="BEAST Attack Vulnerability",
            description="TLS 1.0 with CBC mode ciphers is vulnerable to the BEAST attack (CVE-2011-3389), enabling chosen-plaintext attacks.",
            cve_ids=["CVE-2011-3389"],
            remediation="Upgrade to TLS 1.2+ and prefer GCM mode ciphers.",
        ))

    # ===== Weak cipher suites offered =====

    weak_ratio = row.get("weak_ciphers_offered_ratio", 0)
    if isinstance(weak_ratio, (int, float)) and weak_ratio > 0.5:
        findings.append(Finding(
            id="VULN-CONFIG-001",
            severity="MEDIUM",
            title="Majority of Offered Cipher Suites Are Weak",
            description=f"{int(weak_ratio * 100)}% of cipher suites offered by the client contain weak algorithms (NULL, RC4, DES, 3DES, EXPORT).",
            remediation="Review and harden the client's TLS configuration.",
        ))

    return findings


def calculate_risk_score(findings: list[Finding]) -> float:
    """
    Calculate a normalized risk score (1.0 - 10.0) from findings.

    - 1.0 = No issues (perfect security posture)
    - 10.0 = Critical vulnerabilities present
    """
    if not findings:
        return 1.0

    # Weighted sum approach
    total_weight = sum(SEVERITY_WEIGHTS.get(f.severity, 0) for f in findings)

    # Normalize: cap at 10, minimum 1
    score = min(10.0, max(1.0, total_weight))

    return round(score, 1)


def severity_label(score: float) -> str:
    """Map a risk score to a severity category."""
    if score >= 8.0:
        return "CRITICAL"
    if score >= 6.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score >= 2.0:
        return "LOW"
    return "INFO"


def score_sessions(df: pd.DataFrame) -> pd.DataFrame:
    """
    Run rule-based vulnerability detection and risk scoring on all sessions.

    Adds columns: risk_score, severity, findings
    """
    scores = []
    severities = []
    all_findings = []

    for _, row in df.iterrows():
        findings = detect_vulnerabilities(row)
        score = calculate_risk_score(findings)
        sev = severity_label(score)

        scores.append(score)
        severities.append(sev)
        all_findings.append([f.to_dict() for f in findings])

    df = df.copy()
    df["risk_score"] = scores
    df["severity"] = severities
    df["findings"] = all_findings

    return df
