#!/bin/bash

# Upload PCAP
UPLOAD_RESP=$(curl -s -X POST http://localhost:6000/api/v1/pcaps -F "pcap=@../testdata/sample_traffic.pcap")
PCAP_PATH=$(echo $UPLOAD_RESP | jq -r '.pcap_path')
echo "Uploaded PCAP path: $PCAP_PATH"

# Create Analysis
CREATE_RESP=$(curl -s -X POST http://localhost:6000/api/v1/analyses -H "Content-Type: application/json" -d "{\"pcap_path\": \"$PCAP_PATH\"}")
ANALYSIS_ID=$(echo $CREATE_RESP | jq -r '.id')
echo "Created Analysis ID: $ANALYSIS_ID"

# Start Analysis
curl -s -X POST http://localhost:6000/api/v1/analyses/$ANALYSIS_ID/start > /dev/null
echo "Started Analysis"

# Poll
for i in {1..20}; do
  HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:6000/api/v1/analyses/$ANALYSIS_ID)
  echo "Poll $i: HTTP $HTTP_STATUS"
  if [ "$HTTP_STATUS" == "404" ]; then
    echo "FAILED! 404 Returned!"
  fi
  sleep 0.5
done
