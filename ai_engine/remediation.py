"""
SecureMailScope — Remediation Engine

Maps detected vulnerabilities to exact server configuration fixes for:
- Postfix (SMTP)
- Dovecot (IMAP/POP3)
- Nginx (mail proxy)
- General OpenSSL configuration

Provides copy-paste configuration snippets that administrators can
directly apply to fix identified cryptographic weaknesses.
"""


# ============================================================================
# Recommended secure configurations (2024+ best practices)
# ============================================================================

POSTFIX_SECURE_CONFIG = {
    "tls_protocols": """# Postfix TLS Protocol Configuration
# File: /etc/postfix/main.cf

# Enforce TLS 1.2+ for incoming connections
smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1

# Enforce TLS 1.2+ for outgoing connections
smtp_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtp_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1

# Enable opportunistic TLS for outbound
smtp_tls_security_level = may
smtpd_tls_security_level = may""",

    "tls_ciphers": """# Postfix Cipher Suite Configuration
# File: /etc/postfix/main.cf

# Use strong cipher suites only (AEAD ciphers preferred)
smtpd_tls_mandatory_ciphers = high
smtpd_tls_exclude_ciphers = aNULL, eNULL, EXPORT, DES, RC4, MD5, PSK, aECDH, EDH-DSS-DES-CBC3-SHA, EDH-RSA-DES-CBC3-SHA, KRB5-DES, CBC3-SHA
smtp_tls_mandatory_ciphers = high

# Prefer server cipher order
tls_preempt_cipherlist = yes""",

    "certificate": """# Postfix Certificate Configuration
# File: /etc/postfix/main.cf

# Server certificate and key
smtpd_tls_cert_file = /etc/ssl/certs/mail_server.crt
smtpd_tls_key_file = /etc/ssl/private/mail_server.key
smtpd_tls_CAfile = /etc/ssl/certs/ca-certificates.crt

# Enable certificate verification for outgoing mail
smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt
smtp_tls_verify_cert_match = hostname""",

    "compression": """# Disable TLS compression (CRIME mitigation)
# File: /etc/postfix/main.cf

tls_ssl_options = NO_COMPRESSION""",
}

DOVECOT_SECURE_CONFIG = {
    "tls_protocols": """# Dovecot TLS Protocol Configuration
# File: /etc/dovecot/conf.d/10-ssl.conf

ssl = required

# Minimum TLS version
ssl_min_protocol = TLSv1.2""",

    "tls_ciphers": """# Dovecot Cipher Suite Configuration
# File: /etc/dovecot/conf.d/10-ssl.conf

# Strong cipher suites only
ssl_cipher_list = ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384

# Prefer server cipher order
ssl_prefer_server_ciphers = yes""",

    "certificate": """# Dovecot Certificate Configuration
# File: /etc/dovecot/conf.d/10-ssl.conf

ssl_cert = </etc/ssl/certs/mail_server.crt
ssl_key = </etc/ssl/private/mail_server.key
ssl_ca = </etc/ssl/certs/ca-certificates.crt""",
}

NGINX_MAIL_SECURE_CONFIG = {
    "tls_protocols": """# Nginx Mail Proxy TLS Configuration
# File: /etc/nginx/nginx.conf (mail block)

mail {
    ssl_protocols TLSv1.2 TLSv1.3;
}""",

    "tls_ciphers": """# Nginx Mail Proxy Cipher Configuration
# File: /etc/nginx/nginx.conf (mail block)

mail {
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers on;
}""",

    "certificate": """# Nginx Certificate Configuration
# File: /etc/nginx/nginx.conf

mail {
    ssl_certificate /etc/ssl/certs/mail_server.crt;
    ssl_certificate_key /etc/ssl/private/mail_server.key;
    ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;
}""",
}


# ============================================================================
# Vulnerability → Remediation Mapping
# ============================================================================

REMEDIATION_MAP = {
    # TLS Version Issues
    "VULN-TLS-001": {  # SSLv3
        "category": "Protocol Upgrade",
        "priority": "IMMEDIATE",
        "configs": {
            "Postfix": POSTFIX_SECURE_CONFIG["tls_protocols"],
            "Dovecot": DOVECOT_SECURE_CONFIG["tls_protocols"],
            "Nginx": NGINX_MAIL_SECURE_CONFIG["tls_protocols"],
        },
    },
    "VULN-TLS-002": {  # TLS 1.0
        "category": "Protocol Upgrade",
        "priority": "URGENT",
        "configs": {
            "Postfix": POSTFIX_SECURE_CONFIG["tls_protocols"],
            "Dovecot": DOVECOT_SECURE_CONFIG["tls_protocols"],
            "Nginx": NGINX_MAIL_SECURE_CONFIG["tls_protocols"],
        },
    },
    "VULN-TLS-003": {  # TLS 1.1
        "category": "Protocol Upgrade",
        "priority": "URGENT",
        "configs": {
            "Postfix": POSTFIX_SECURE_CONFIG["tls_protocols"],
            "Dovecot": DOVECOT_SECURE_CONFIG["tls_protocols"],
            "Nginx": NGINX_MAIL_SECURE_CONFIG["tls_protocols"],
        },
    },
    "VULN-TLS-010": {  # No TLS
        "category": "Enable Encryption",
        "priority": "IMMEDIATE",
        "configs": {
            "Postfix": POSTFIX_SECURE_CONFIG["tls_protocols"] + "\n\n" + POSTFIX_SECURE_CONFIG["certificate"],
            "Dovecot": DOVECOT_SECURE_CONFIG["tls_protocols"] + "\n\n" + DOVECOT_SECURE_CONFIG["certificate"],
        },
    },
    # Cipher Issues
    "VULN-CIPHER-001": {  # NULL cipher
        "category": "Cipher Hardening",
        "priority": "IMMEDIATE",
        "configs": {
            "Postfix": POSTFIX_SECURE_CONFIG["tls_ciphers"],
            "Dovecot": DOVECOT_SECURE_CONFIG["tls_ciphers"],
            "Nginx": NGINX_MAIL_SECURE_CONFIG["tls_ciphers"],
        },
    },
    "VULN-CIPHER-002": {  # RC4
        "category": "Cipher Hardening",
        "priority": "URGENT",
        "configs": {
            "Postfix": POSTFIX_SECURE_CONFIG["tls_ciphers"],
            "Dovecot": DOVECOT_SECURE_CONFIG["tls_ciphers"],
            "Nginx": NGINX_MAIL_SECURE_CONFIG["tls_ciphers"],
        },
    },
    "VULN-CIPHER-003": {  # 3DES / SWEET32
        "category": "Cipher Hardening",
        "priority": "HIGH",
        "configs": {
            "Postfix": POSTFIX_SECURE_CONFIG["tls_ciphers"],
            "Dovecot": DOVECOT_SECURE_CONFIG["tls_ciphers"],
            "Nginx": NGINX_MAIL_SECURE_CONFIG["tls_ciphers"],
        },
    },
    "VULN-CIPHER-004": {  # Export ciphers / FREAK
        "category": "Cipher Hardening",
        "priority": "IMMEDIATE",
        "configs": {
            "Postfix": POSTFIX_SECURE_CONFIG["tls_ciphers"],
            "Dovecot": DOVECOT_SECURE_CONFIG["tls_ciphers"],
        },
    },
    # Forward Secrecy
    "VULN-KEX-001": {
        "category": "Key Exchange Upgrade",
        "priority": "HIGH",
        "configs": {
            "Postfix": POSTFIX_SECURE_CONFIG["tls_ciphers"],
            "Dovecot": DOVECOT_SECURE_CONFIG["tls_ciphers"],
        },
    },
    # Compression
    "VULN-COMP-001": {  # CRIME
        "category": "Compression",
        "priority": "URGENT",
        "configs": {
            "Postfix": POSTFIX_SECURE_CONFIG["compression"],
        },
    },
    # Certificate Issues
    "VULN-CERT-001": {  # Expired
        "category": "Certificate Renewal",
        "priority": "IMMEDIATE",
        "configs": {
            "Postfix": POSTFIX_SECURE_CONFIG["certificate"],
            "Dovecot": DOVECOT_SECURE_CONFIG["certificate"],
            "Nginx": NGINX_MAIL_SECURE_CONFIG["certificate"],
            "ACME/Certbot": """# Automated certificate renewal with Certbot
# Install: sudo apt install certbot

# Obtain certificate
sudo certbot certonly --standalone -d mail.yourdomain.com

# Auto-renew (add to crontab)
0 0 1 * * certbot renew --post-hook "systemctl reload postfix dovecot" """,
        },
    },
    "VULN-CERT-002": {  # Self-signed
        "category": "Certificate Authority",
        "priority": "HIGH",
        "configs": {
            "ACME/Certbot": """# Replace self-signed cert with Let's Encrypt
sudo certbot certonly --standalone -d mail.yourdomain.com

# Update Postfix
# smtpd_tls_cert_file = /etc/letsencrypt/live/mail.yourdomain.com/fullchain.pem
# smtpd_tls_key_file = /etc/letsencrypt/live/mail.yourdomain.com/privkey.pem

# Update Dovecot
# ssl_cert = </etc/letsencrypt/live/mail.yourdomain.com/fullchain.pem
# ssl_key = </etc/letsencrypt/live/mail.yourdomain.com/privkey.pem""",
        },
    },
    "VULN-CERT-003": {  # Weak key
        "category": "Key Regeneration",
        "priority": "IMMEDIATE",
        "configs": {
            "OpenSSL": """# Generate new RSA 4096-bit key and CSR
openssl req -newkey rsa:4096 -keyout mail_server.key -out mail_server.csr -nodes \\
    -subj "/C=IN/ST=State/L=City/O=Organization/CN=mail.yourdomain.com"

# Or use ECDSA P-256 (faster, equally secure)
openssl ecparam -genkey -name prime256v1 -out mail_server.key
openssl req -new -key mail_server.key -out mail_server.csr \\
    -subj "/C=IN/ST=State/L=City/O=Organization/CN=mail.yourdomain.com" """,
        },
    },
    "VULN-CERT-004": {  # Weak signature
        "category": "Certificate Reissuance",
        "priority": "URGENT",
        "configs": {
            "OpenSSL": """# Reissue with SHA-256 signature
openssl req -new -key mail_server.key -out mail_server.csr -sha256 \\
    -subj "/C=IN/ST=State/L=City/O=Organization/CN=mail.yourdomain.com"

# Self-sign with SHA-256 (for testing)
openssl x509 -req -in mail_server.csr -signkey mail_server.key \\
    -out mail_server.crt -days 365 -sha256""",
        },
    },
    "VULN-CERT-005": {  # Expiring soon
        "category": "Certificate Renewal",
        "priority": "HIGH",
        "configs": {
            "ACME/Certbot": """# Renew certificate before expiration
sudo certbot renew

# Force renewal
sudo certbot renew --force-renewal

# Reload services after renewal
sudo systemctl reload postfix dovecot""",
        },
    },
    # BEAST
    "VULN-BEAST-001": {
        "category": "Protocol + Cipher Upgrade",
        "priority": "URGENT",
        "configs": {
            "Postfix": POSTFIX_SECURE_CONFIG["tls_protocols"] + "\n\n" + POSTFIX_SECURE_CONFIG["tls_ciphers"],
        },
    },
    # Weak cipher config
    "VULN-CONFIG-001": {
        "category": "Client Hardening",
        "priority": "MEDIUM",
        "configs": {
            "Note": "This finding relates to the client's cipher suite configuration, not the server. Review the email client or MTA that is initiating the connection.",
        },
    },
}


def generate_remediation(findings: list[dict]) -> list[dict]:
    """
    Generate remediation recommendations for a list of findings.

    Args:
        findings: List of finding dicts from risk_scorer.

    Returns:
        List of remediation recommendation dicts.
    """
    remediations = []
    seen_categories = set()

    for finding in findings:
        vuln_id = finding.get("id", "")
        remap = REMEDIATION_MAP.get(vuln_id)

        if not remap:
            # Generic remediation for unmapped vulnerabilities
            remediations.append({
                "finding_id": vuln_id,
                "finding_title": finding.get("title", ""),
                "category": "General",
                "priority": finding.get("severity", "MEDIUM"),
                "remediation_text": finding.get("remediation", "Review and address this finding."),
                "config_snippets": {},
            })
            continue

        category = remap["category"]
        if category in seen_categories:
            # Avoid duplicate config snippets for the same category
            remediations.append({
                "finding_id": vuln_id,
                "finding_title": finding.get("title", ""),
                "category": category,
                "priority": remap["priority"],
                "remediation_text": finding.get("remediation", ""),
                "config_snippets": {},  # Already provided above
                "note": f"Configuration fix already included under '{category}' above.",
            })
            continue

        seen_categories.add(category)
        remediations.append({
            "finding_id": vuln_id,
            "finding_title": finding.get("title", ""),
            "category": category,
            "priority": remap["priority"],
            "remediation_text": finding.get("remediation", ""),
            "config_snippets": remap["configs"],
        })

    # Sort by priority
    priority_order = {"IMMEDIATE": 0, "URGENT": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4}
    remediations.sort(key=lambda x: priority_order.get(x["priority"], 5))

    return remediations
