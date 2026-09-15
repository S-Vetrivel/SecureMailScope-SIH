#!/usr/bin/env bash
# =============================================================================
# SecureMailScope — Synthetic Email Traffic Generator
# Generates PCAP files with SMTP/IMAP/POP3 traffic containing various TLS configs
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CERT_DIR="$SCRIPT_DIR/certs"
OUTPUT_DIR="$SCRIPT_DIR/output"
mkdir -p "$OUTPUT_DIR"

# Check prerequisites
for cmd in openssl tcpdump; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "ERROR: '$cmd' is required but not installed."
        exit 1
    fi
done

echo "=== SecureMailScope Traffic Generator ==="
echo "Cert directory: $CERT_DIR"
echo "Output directory: $OUTPUT_DIR"
echo ""

# Helper: capture traffic on a port pair
# Usage: capture_session <name> <server_port> <cert> <key> <tls_flags> <client_flags> <protocol>
capture_session() {
    local name="$1"
    local port="$2"
    local cert="$3"
    local key="$4"
    local server_flags="$5"
    local client_flags="$6"
    local protocol="$7"
    local pcap_file="$OUTPUT_DIR/${name}.pcap"

    echo "  Capturing: $name (port $port, $protocol)..."

    # Start tcpdump in background
    sudo tcpdump -i lo port "$port" -w "$pcap_file" -c 100 &>/dev/null &
    local tcpdump_pid=$!
    sleep 0.5

    # Start openssl s_server
    # shellcheck disable=SC2086
    openssl s_server -accept "$port" -cert "$cert" -key "$key" \
        $server_flags -quiet -naccept 1 &>/dev/null &
    local server_pid=$!
    sleep 0.5

    # Connect with openssl s_client
    # shellcheck disable=SC2086
    echo -e "EHLO test.local\r\nQUIT\r\n" | \
        openssl s_client -connect "127.0.0.1:$port" \
        $client_flags -quiet &>/dev/null 2>&1 || true
    sleep 0.5

    # Cleanup
    kill "$server_pid" 2>/dev/null || true
    sleep 0.5
    sudo kill "$tcpdump_pid" 2>/dev/null || true
    wait "$tcpdump_pid" 2>/dev/null || true

    if [ -f "$pcap_file" ]; then
        local size
        size=$(stat -f%z "$pcap_file" 2>/dev/null || stat -c%s "$pcap_file" 2>/dev/null || echo "0")
        echo "    ✓ $pcap_file ($size bytes)"
    else
        echo "    ✗ Failed to create $pcap_file"
    fi
}

# Helper for STARTTLS simulation
capture_starttls_session() {
    local name="$1"
    local port="$2"
    local cert="$3"
    local key="$4"
    local server_flags="$5"
    local pcap_file="$OUTPUT_DIR/${name}.pcap"

    echo "  Capturing STARTTLS: $name (port $port)..."

    # Start tcpdump
    sudo tcpdump -i lo port "$port" -w "$pcap_file" -c 200 &>/dev/null &
    local tcpdump_pid=$!
    sleep 0.5

    # Start openssl s_server with -starttls smtp mode isn't available on server side
    # Instead we use a simple approach: s_server in accept mode
    # shellcheck disable=SC2086
    openssl s_server -accept "$port" -cert "$cert" -key "$key" \
        $server_flags -quiet -naccept 1 &>/dev/null &
    local server_pid=$!
    sleep 0.5

    # Client with STARTTLS
    echo -e "EHLO test.local\r\nSTARTTLS\r\n" | \
        openssl s_client -connect "127.0.0.1:$port" -starttls smtp \
        -quiet &>/dev/null 2>&1 || true
    sleep 0.5

    kill "$server_pid" 2>/dev/null || true
    sleep 0.5
    sudo kill "$tcpdump_pid" 2>/dev/null || true
    wait "$tcpdump_pid" 2>/dev/null || true

    if [ -f "$pcap_file" ]; then
        local size
        size=$(stat -f%z "$pcap_file" 2>/dev/null || stat -c%s "$pcap_file" 2>/dev/null || echo "0")
        echo "    ✓ $pcap_file ($size bytes)"
    else
        echo "    ✗ Failed to create $pcap_file"
    fi
}

# ============================================================================
# Scenario 1: SMTPS with valid certificate (TLS 1.2 + strong cipher)
# ============================================================================
echo "[Scenario 1] SMTPS — Valid cert, TLS 1.2, strong ciphers"
capture_session "smtps_valid_tls12" 10465 \
    "$CERT_DIR/valid_server.crt" "$CERT_DIR/valid_server.key" \
    "-tls1_2" "-tls1_2" "SMTPS"

# ============================================================================
# Scenario 2: SMTPS with valid certificate (TLS 1.3)
# ============================================================================
echo "[Scenario 2] SMTPS — Valid cert, TLS 1.3"
capture_session "smtps_valid_tls13" 10466 \
    "$CERT_DIR/valid_server.crt" "$CERT_DIR/valid_server.key" \
    "-tls1_3" "-tls1_3" "SMTPS"

# ============================================================================
# Scenario 3: SMTPS with expired certificate
# ============================================================================
echo "[Scenario 3] SMTPS — Expired cert"
if [ -f "$CERT_DIR/expired_server.crt" ]; then
    capture_session "smtps_expired_cert" 10467 \
        "$CERT_DIR/expired_server.crt" "$CERT_DIR/expired_server.key" \
        "-tls1_2" "-tls1_2" "SMTPS"
else
    echo "  ⚠ Skipped (expired cert not generated)"
fi

# ============================================================================
# Scenario 4: SMTPS with weak key (RSA 1024 + SHA-1)
# ============================================================================
echo "[Scenario 4] SMTPS — Weak cert (RSA 1024, SHA-1)"
if [ -f "$CERT_DIR/weak_server.crt" ]; then
    capture_session "smtps_weak_key" 10468 \
        "$CERT_DIR/weak_server.crt" "$CERT_DIR/weak_server.key" \
        "-tls1_2" "-tls1_2" "SMTPS"
else
    echo "  ⚠ Skipped (weak cert not generated)"
fi

# ============================================================================
# Scenario 5: SMTPS with self-signed certificate
# ============================================================================
echo "[Scenario 5] SMTPS — Self-signed cert"
capture_session "smtps_selfsigned" 10469 \
    "$CERT_DIR/selfsigned_server.crt" "$CERT_DIR/selfsigned_server.key" \
    "-tls1_2" "-tls1_2" "SMTPS"

# ============================================================================
# Scenario 6: SMTPS with TLS 1.0 (deprecated)
# ============================================================================
echo "[Scenario 6] SMTPS — TLS 1.0 (DEPRECATED)"
capture_session "smtps_tls10" 10470 \
    "$CERT_DIR/valid_server.crt" "$CERT_DIR/valid_server.key" \
    "-tls1" "-tls1" "SMTPS" 2>/dev/null || echo "  ⚠ TLS 1.0 not supported by this OpenSSL build"

# ============================================================================
# Scenario 7: SMTPS with TLS 1.1 (deprecated)
# ============================================================================
echo "[Scenario 7] SMTPS — TLS 1.1 (DEPRECATED)"
capture_session "smtps_tls11" 10471 \
    "$CERT_DIR/valid_server.crt" "$CERT_DIR/valid_server.key" \
    "-tls1_1" "-tls1_1" "SMTPS" 2>/dev/null || echo "  ⚠ TLS 1.1 not supported by this OpenSSL build"

# ============================================================================
# Scenario 8: IMAPS with valid certificate (TLS 1.2)
# ============================================================================
echo "[Scenario 8] IMAPS — Valid cert, TLS 1.2"
capture_session "imaps_valid_tls12" 10993 \
    "$CERT_DIR/valid_server.crt" "$CERT_DIR/valid_server.key" \
    "-tls1_2" "-tls1_2" "IMAPS"

# ============================================================================
# Scenario 9: IMAPS with self-signed cert
# ============================================================================
echo "[Scenario 9] IMAPS — Self-signed cert"
capture_session "imaps_selfsigned" 10994 \
    "$CERT_DIR/selfsigned_server.crt" "$CERT_DIR/selfsigned_server.key" \
    "-tls1_2" "-tls1_2" "IMAPS"

# ============================================================================
# Scenario 10: POP3S with valid certificate (TLS 1.2)
# ============================================================================
echo "[Scenario 10] POP3S — Valid cert, TLS 1.2"
capture_session "pop3s_valid_tls12" 10995 \
    "$CERT_DIR/valid_server.crt" "$CERT_DIR/valid_server.key" \
    "-tls1_2" "-tls1_2" "POP3S"

# ============================================================================
# Scenario 11: POP3S with weak key
# ============================================================================
echo "[Scenario 11] POP3S — Weak key cert"
if [ -f "$CERT_DIR/weak_server.crt" ]; then
    capture_session "pop3s_weak_key" 10996 \
        "$CERT_DIR/weak_server.crt" "$CERT_DIR/weak_server.key" \
        "-tls1_2" "-tls1_2" "POP3S"
else
    echo "  ⚠ Skipped (weak cert not generated)"
fi

# ============================================================================
# Scenario 12: SMTP STARTTLS with valid cert
# ============================================================================
echo "[Scenario 12] SMTP STARTTLS — Valid cert"
capture_starttls_session "smtp_starttls_valid" 10587 \
    "$CERT_DIR/valid_server.crt" "$CERT_DIR/valid_server.key" \
    "-tls1_2"

echo ""
echo "=== Traffic Generation Complete ==="
echo "PCAP files created in: $OUTPUT_DIR"
ls -la "$OUTPUT_DIR"/*.pcap 2>/dev/null || echo "No PCAP files found (might need sudo)"
