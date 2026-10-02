#!/bin/bash
echo "Starting tcpdump (background)..."
sudo tcpdump -i tailscale0 -nn -w /tmp/tcpdump_test.pcap 'tcp port 25 or tcp port 465 or tcp port 587 or tcp port 110 or tcp port 995 or tcp port 143 or tcp port 993' &
TCPDUMP_PID=$!

sleep 1

echo "Starting dumpcap (background)..."
sudo /usr/bin/dumpcap -i tailscale0 -a duration:5 -w /tmp/dumpcap_test.pcap -q -F pcap -f "tcp port 25 or tcp port 465 or tcp port 587 or tcp port 110 or tcp port 995 or tcp port 143 or tcp port 993" &
DUMPCAP_PID=$!

sleep 1

echo "Sending SMTP traffic..."
printf 'EHLO test.local\r\nQUIT\r\n' | openssl s_client -connect 100.71.131.67:587 -starttls smtp -servername mail.velotriz.cloud -quiet

sleep 5

kill $TCPDUMP_PID 2>/dev/null
wait $TCPDUMP_PID 2>/dev/null

echo "--- RESULTS ---"
ls -la /tmp/tcpdump_test.pcap /tmp/dumpcap_test.pcap
echo "tcpdump packets:"
tcpdump -r /tmp/tcpdump_test.pcap -nn | wc -l
echo "dumpcap packets:"
tcpdump -r /tmp/dumpcap_test.pcap -nn | wc -l
