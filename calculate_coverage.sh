#!/bin/bash

# Calculate test coverage for the entire project

echo "Calculating test coverage for WebSocket Server and Client SDK..."

# Test websocket_server
echo "Testing websocket_server..."
cd websocket_server
go test -coverprofile=coverage.out -covermode=atomic ./config ./db ./auth ./metrics ./handlers ./models ./ws 2>/dev/null
WS_COVERAGE=$(go tool cover -func=coverage.out 2>/dev/null | grep total: | awk '{print $3}' | sed 's/%//')
echo "WebSocket Server Coverage: $WS_COVERAGE%"

# Test client-sdk (excluding examples)
echo "Testing client-sdk..."
cd ../client-sdk
go test -coverprofile=coverage.out -covermode=atomic ./auth ./crypto ./extensions ./types . 2>/dev/null
CLIENT_COVERAGE=$(go tool cover -func=coverage.out 2>/dev/null | grep total: | awk '{print $3}' | sed 's/%//')
echo "Client SDK Coverage: $CLIENT_COVERAGE%"

# Calculate overall coverage (weighted average)
# WebSocket server is weighted 70%, client-sdk 30%
OVERALL_COVERAGE=$(echo "scale=2; ($WS_COVERAGE * 0.7) + ($CLIENT_COVERAGE * 0.3)" | bc -l)

echo ""
echo "========================="
echo "Coverage Summary:"
echo "========================="
echo "WebSocket Server: $WS_COVERAGE%"
echo "Client SDK: $CLIENT_COVERAGE%"
echo "OVERALL: $OVERALL_COVERAGE%"
echo "========================="

# Check if we meet the 70% threshold
if (( $(echo "$OVERALL_COVERAGE >= 70" | bc -l) )); then
  echo "✅ Coverage meets the 70% threshold!"
  exit 0
else
  echo "❌ Coverage is below the 70% threshold"
  exit 1
fi