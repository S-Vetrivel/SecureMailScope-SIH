#!/bin/bash
set -e

echo "=== SecureMailScope Analysis Regression Test ==="

echo "1. Uploading PCAP..."
UPLOAD_RESP=$(curl -s -X POST http://localhost:6000/api/v1/pcaps -F "pcap=@../testdata/sample_traffic.pcap")
PCAP_PATH=$(echo $UPLOAD_RESP | jq -r '.pcap_path')
if [ "$PCAP_PATH" == "null" ] || [ -z "$PCAP_PATH" ]; then
    echo "Upload failed: $UPLOAD_RESP"
    exit 1
fi
echo "✓ PCAP uploaded successfully: $PCAP_PATH"

echo "2. Creating Analysis..."
CREATE_RESP=$(curl -s -X POST http://localhost:6000/api/v1/analyses -H "Content-Type: application/json" -d "{\"pcap_path\": \"$PCAP_PATH\"}")
ANALYSIS_ID=$(echo $CREATE_RESP | jq -r '.id')
if [ "$ANALYSIS_ID" == "null" ] || [ -z "$ANALYSIS_ID" ]; then
    echo "Create analysis failed: $CREATE_RESP"
    exit 1
fi
echo "✓ Analysis record created: $ANALYSIS_ID"

echo "3. Starting Analysis..."
START_HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:6000/api/v1/analyses/$ANALYSIS_ID/start)
if [ "$START_HTTP_CODE" != "200" ]; then
    echo "Start analysis failed with HTTP $START_HTTP_CODE"
    exit 1
fi
echo "✓ Analysis pipeline started"

echo "4. Polling status continuously..."
COMPLETED=0
for i in {1..30}; do
    STATUS_JSON=$(curl -s http://localhost:6000/api/v1/analyses/$ANALYSIS_ID)
    
    # Check if we got a JSON response with an error
    ERROR_CODE=$(echo $STATUS_JSON | jq -r '.error.code' 2>/dev/null)
    if [ "$ERROR_CODE" == "NOT_FOUND" ]; then
        echo "❌ REGRESSION DETECTED: Endpoint returned 404 NOT_FOUND during processing!"
        exit 1
    fi

    STATUS=$(echo $STATUS_JSON | jq -r '.status' 2>/dev/null)
    echo "   Poll $i: Status = $STATUS"
    
    if [ "$STATUS" == "COMPLETED" ]; then
        COMPLETED=1
        break
    fi
    sleep 0.5
done

if [ "$COMPLETED" -eq 0 ]; then
    echo "❌ Test failed: Analysis did not complete within timeout."
    exit 1
fi
echo "✓ Analysis completed successfully"

echo "5. Verifying final record availability..."
FINAL_HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:6000/api/v1/analyses/$ANALYSIS_ID)
if [ "$FINAL_HTTP_CODE" == "404" ]; then
    echo "❌ REGRESSION DETECTED: Endpoint returned 404 after completion!"
    exit 1
fi
echo "✓ Final record is available (HTTP 200)"

echo "6. Verifying results availability..."
SCORE=$(curl -s http://localhost:6000/api/v1/analyses/$ANALYSIS_ID | jq -r '.overall_score')
if [ "$SCORE" == "null" ]; then
    echo "❌ REGRESSION DETECTED: Results missing!"
    exit 1
fi
echo "✓ Results persisted correctly. Overall Score: $SCORE"

echo "=== All Tests Passed ==="
