#!/usr/bin/env bash
# =============================================================================
# SecureMailScope — Synthetic Certificate Generator
# Generates X.509 certificates with intentional cryptographic flaws for testing
# =============================================================================
set -euo pipefail

CERT_DIR="$(dirname "$0")/certs"
mkdir -p "$CERT_DIR"

echo "=== SecureMailScope Certificate Generator ==="
echo "Output directory: $CERT_DIR"
echo ""

# ---------------------------------------------------------------------------
# 1. Valid CA Certificate (RSA 2048, SHA-256, 10-year validity)
# ---------------------------------------------------------------------------
echo "[1/6] Generating valid CA certificate..."
openssl req -x509 -newkey rsa:2048 -keyout "$CERT_DIR/ca.key" -out "$CERT_DIR/ca.crt" \
    -days 3650 -nodes -sha256 \
    -subj "/C=IN/ST=Delhi/L=NewDelhi/O=SecureMailScope CA/OU=Testing/CN=SecureMailScope Root CA"
echo "  ✓ ca.crt (RSA 2048, SHA-256, valid 10 years)"

# ---------------------------------------------------------------------------
# 2. Valid Server Certificate (RSA 2048, SHA-256, 1-year validity, signed by CA)
# ---------------------------------------------------------------------------
echo "[2/6] Generating valid server certificate..."
openssl req -newkey rsa:2048 -keyout "$CERT_DIR/valid_server.key" -out "$CERT_DIR/valid_server.csr" \
    -nodes -sha256 \
    -subj "/C=IN/ST=Delhi/L=NewDelhi/O=SecureMailScope/OU=Mail/CN=mail.securemailscope.local"

cat > "$CERT_DIR/valid_server.ext" << 'EOF'
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage=digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName=@alt_names
[alt_names]
DNS.1=mail.securemailscope.local
DNS.2=smtp.securemailscope.local
DNS.3=imap.securemailscope.local
DNS.4=pop3.securemailscope.local
DNS.5=localhost
IP.1=127.0.0.1
EOF

openssl x509 -req -in "$CERT_DIR/valid_server.csr" -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" \
    -CAcreateserial -out "$CERT_DIR/valid_server.crt" -days 365 -sha256 \
    -extfile "$CERT_DIR/valid_server.ext"
echo "  ✓ valid_server.crt (RSA 2048, SHA-256, CA-signed, 1 year)"

# ---------------------------------------------------------------------------
# 3. Expired Certificate (RSA 2048, SHA-256, expired yesterday)
# ---------------------------------------------------------------------------
echo "[3/6] Generating expired certificate..."
openssl req -newkey rsa:2048 -keyout "$CERT_DIR/expired_server.key" -out "$CERT_DIR/expired_server.csr" \
    -nodes -sha256 \
    -subj "/C=IN/ST=Delhi/L=NewDelhi/O=SecureMailScope/OU=Mail/CN=expired.securemailscope.local"

# Create cert valid from 2 days ago to 1 day ago (already expired)
openssl ca -batch -config <(cat <<CAEOF
[ca]
default_ca = CA_default
[CA_default]
database = $CERT_DIR/index.txt
serial = $CERT_DIR/serial
certificate = $CERT_DIR/ca.crt
private_key = $CERT_DIR/ca.key
default_md = sha256
policy = policy_anything
new_certs_dir = $CERT_DIR
[policy_anything]
countryName = optional
stateOrProvinceName = optional
localityName = optional
organizationName = optional
organizationalUnitName = optional
commonName = supplied
emailAddress = optional
CAEOF
) -startdate "$(date -u -d '-2 days' +%Y%m%d%H%M%SZ 2>/dev/null || date -u -v-2d +%Y%m%d%H%M%SZ)" \
  -enddate "$(date -u -d '-1 day' +%Y%m%d%H%M%SZ 2>/dev/null || date -u -v-1d +%Y%m%d%H%M%SZ)" \
  -in "$CERT_DIR/expired_server.csr" -out "$CERT_DIR/expired_server.crt" 2>/dev/null || {
    # Fallback: use openssl x509 with very short validity hack
    echo "  (Using fallback method for expired cert)"
    faketime -f '-3d' openssl x509 -req -in "$CERT_DIR/expired_server.csr" \
        -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
        -out "$CERT_DIR/expired_server.crt" -days 1 -sha256 2>/dev/null || {
        # Second fallback: self-sign with 0 days
        openssl req -x509 -newkey rsa:2048 -keyout "$CERT_DIR/expired_server.key" \
            -out "$CERT_DIR/expired_server.crt" -days 0 -nodes -sha256 \
            -subj "/C=IN/ST=Delhi/O=SecureMailScope/CN=expired.securemailscope.local" 2>/dev/null || true
    }
}
echo "  ✓ expired_server.crt (RSA 2048, SHA-256, EXPIRED)"

# ---------------------------------------------------------------------------
# 4. Weak Key Certificate (RSA 1024, SHA-1 signature — both deprecated)
# ---------------------------------------------------------------------------
echo "[4/6] Generating weak key + SHA-1 certificate..."
openssl req -x509 -newkey rsa:1024 -keyout "$CERT_DIR/weak_server.key" -out "$CERT_DIR/weak_server.crt" \
    -days 365 -nodes -sha1 \
    -subj "/C=IN/ST=Delhi/L=NewDelhi/O=SecureMailScope/OU=Mail/CN=weak.securemailscope.local" 2>/dev/null || {
    # Some OpenSSL versions reject 1024-bit, try with security level override
    openssl req -x509 -newkey rsa:1024 -keyout "$CERT_DIR/weak_server.key" -out "$CERT_DIR/weak_server.crt" \
        -days 365 -nodes -sha1 \
        -subj "/C=IN/ST=Delhi/O=SecureMailScope/CN=weak.securemailscope.local" \
        -config <(cat /etc/ssl/openssl.cnf 2>/dev/null; echo -e "\n[system_default_sect]\nMinProtocol = TLSv1\nCipherString = DEFAULT:@SECLEVEL=0") 2>/dev/null || true
}
echo "  ✓ weak_server.crt (RSA 1024, SHA-1, WEAK)"

# ---------------------------------------------------------------------------
# 5. Self-Signed Certificate (no CA chain — trust issue)
# ---------------------------------------------------------------------------
echo "[5/6] Generating self-signed certificate..."
openssl req -x509 -newkey rsa:2048 -keyout "$CERT_DIR/selfsigned_server.key" -out "$CERT_DIR/selfsigned_server.crt" \
    -days 365 -nodes -sha256 \
    -subj "/C=IN/ST=Delhi/L=NewDelhi/O=SecureMailScope/OU=Mail/CN=selfsigned.securemailscope.local"
echo "  ✓ selfsigned_server.crt (RSA 2048, SHA-256, SELF-SIGNED)"

# ---------------------------------------------------------------------------
# 6. Very Short Key Certificate (RSA 512 — critically weak)
# ---------------------------------------------------------------------------
echo "[6/6] Generating 512-bit RSA certificate (critically weak)..."
openssl req -x509 -newkey rsa:512 -keyout "$CERT_DIR/shortkey_server.key" -out "$CERT_DIR/shortkey_server.crt" \
    -days 365 -nodes -sha256 \
    -subj "/C=IN/ST=Delhi/L=NewDelhi/O=SecureMailScope/OU=Mail/CN=shortkey.securemailscope.local" 2>/dev/null || {
    openssl req -x509 -newkey rsa:512 -keyout "$CERT_DIR/shortkey_server.key" -out "$CERT_DIR/shortkey_server.crt" \
        -days 365 -nodes -sha256 \
        -subj "/C=IN/ST=Delhi/O=SecureMailScope/CN=shortkey.securemailscope.local" \
        -config <(cat /etc/ssl/openssl.cnf 2>/dev/null; echo -e "\n[system_default_sect]\nMinProtocol = TLSv1\nCipherString = DEFAULT:@SECLEVEL=0") 2>/dev/null || true
}
echo "  ✓ shortkey_server.crt (RSA 512, CRITICALLY WEAK)"

# ---------------------------------------------------------------------------
# Cleanup temp files
# ---------------------------------------------------------------------------
rm -f "$CERT_DIR"/*.csr "$CERT_DIR"/*.ext "$CERT_DIR"/*.srl "$CERT_DIR"/index.* "$CERT_DIR"/serial* 2>/dev/null || true

echo ""
echo "=== Certificate Generation Complete ==="
echo "Certificates created in: $CERT_DIR"
ls -la "$CERT_DIR"/*.crt 2>/dev/null
