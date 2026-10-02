#!/bin/bash
set -e

# Create required directories if they don't exist
mkdir -p /data/database /data/captures/live /data/reports /data/uploads

echo "[STARTUP] Validating system requirements..."

# Check TShark
if command -v tshark &> /dev/null; then
    echo "[STARTUP] TShark available: $(tshark --version | head -n 1)"
else
    echo "[STARTUP] Warning: TShark is not installed!"
fi

# Check Python
if command -v python3 &> /dev/null; then
    echo "[STARTUP] Python available: $(python3 --version)"
else
    echo "[STARTUP] Warning: Python is not installed!"
fi

# Check Ollama
if [ "${OLLAMA_ENABLED}" = "true" ]; then
    echo "[STARTUP] Checking Ollama at ${OLLAMA_BASE_URL}..."
    if curl -s -f --connect-timeout 2 "${OLLAMA_BASE_URL}/api/tags" &> /dev/null; then
        echo "[STARTUP] Ollama is available."
    else
        echo "[STARTUP] Warning: Ollama is unreachable at ${OLLAMA_BASE_URL}. Core forensic analysis will continue."
    fi
fi

# Log interfaces
echo "[STARTUP] Available network interfaces for capture:"
ip link show | grep -E '^[0-9]+:' | awk -F: '{print $2}' | sed 's/^[ \t]*//'

echo "[STARTUP] Starting SecureMailScope Backend internally on port 8000..."
export PORT=8000
/app/server &
BACKEND_PID=$!

echo "[STARTUP] Starting Internal Nginx on port 6000..."
nginx -g "daemon off;"
