#!/bin/bash
set -e

mkdir -p pcaps
cd pcaps

echo "Generating certificates..."
# GOOD Certificate
openssl req -x509 -newkey rsa:2048 -keyout good_key.pem -out good_cert.pem -days 365 -nodes -subj "/CN=good.mail.com"

# BAD Certificate (Soon to expire, weak key)
openssl req -x509 -newkey rsa:1024 -keyout bad_key.pem -out bad_cert.pem -days 1 -nodes -subj "/CN=bad.mail.com"

echo "Generating GOOD PCAP (TLS 1.3, strong cipher)..."
tshark -i lo -f "port 2525" -w good_smtp.pcap &
TCPDUMP_PID=$!
sleep 1

openssl s_server -accept 2525 -cert good_cert.pem -key good_key.pem -tls1_3 -ciphersuites TLS_AES_256_GCM_SHA384 -nocert &
SERVER_PID=$!
sleep 1

echo -e "EHLO client\nSTARTTLS\nQUIT\n" | openssl s_client -connect localhost:2525 -tls1_3 -ciphersuites TLS_AES_256_GCM_SHA384
sleep 1
kill $SERVER_PID
kill $TCPDUMP_PID
sleep 1

echo "Generating BAD PCAP (TLS 1.0, weak cipher, expired cert)..."
tshark -i lo -f "port 2526" -w bad_smtp.pcap &
TCPDUMP_PID=$!
sleep 1

openssl s_server -accept 2526 -cert bad_cert.pem -key bad_key.pem -tls1 -cipher RC4-SHA -nocert &
SERVER_PID=$!
sleep 1

echo -e "EHLO client\nSTARTTLS\nQUIT\n" | openssl s_client -connect localhost:2526 -tls1 -cipher RC4-SHA
sleep 1
kill $SERVER_PID
kill $TCPDUMP_PID
sleep 1

echo "Done!"
