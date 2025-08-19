#!/bin/bash

# Quick Start Script for Server Messages Example
# This script demonstrates how to run the server messages example

set -e

echo "=== WebSocket Server Messages Example ==="
echo ""

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "❌ Go is not installed. Please install Go 1.21 or later."
    exit 1
fi

echo "✓ Go is installed: $(go version)"
echo ""

# Function to check if port is in use
check_port() {
    if lsof -Pi :$1 -sTCP:LISTEN -t >/dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

# Function to cleanup background processes
cleanup() {
    echo ""
    echo "🧹 Cleaning up..."
    if [ ! -z "$SERVER_PID" ]; then
        kill $SERVER_PID 2>/dev/null || true
        echo "Stopped server (PID: $SERVER_PID)"
    fi
    exit 0
}

# Set trap to cleanup on exit
trap cleanup SIGINT SIGTERM EXIT

echo "📋 Setting up example..."

# Create directories if they don't exist
mkdir -p server client

# Build the server
echo "🔨 Building server..."
cd server
if [ ! -f go.mod ]; then
    echo "❌ go.mod not found in server directory"
    exit 1
fi

go mod tidy
go build -o server main.go

echo "✓ Server built successfully"

# Check if port 8080 is available
if check_port 8080; then
    echo "⚠️  Port 8080 is already in use. The server might not start properly."
    echo "   Please stop any services using port 8080 and try again."
    read -p "   Continue anyway? (y/N): " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

echo ""
echo "🚀 Starting server..."
./server &
SERVER_PID=$!

echo "✓ Server started (PID: $SERVER_PID)"
echo ""

# Wait a moment for server to start
sleep 2

echo "🌐 Server should be running on http://localhost:8080"
echo ""

# Build the client
echo "🔨 Building client..."
cd ../client
if [ ! -f go.mod ]; then
    echo "❌ go.mod not found in client directory"
    exit 1
fi

go mod tidy
go build -o client main.go

echo "✓ Client built successfully"
echo ""

echo "📖 The client will show example message structures."
echo "   Note: Full functionality requires server integration."
echo ""

echo "▶️  Starting client..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Run the client
./client

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🎉 Example completed!"
echo ""
echo "📚 Next steps:"
echo "   1. Study the custom handlers in server/main.go"
echo "   2. Examine the message structures in client/main.go"
echo "   3. Implement your own custom server message handlers"
echo "   4. Integrate server messages into your application"
echo ""
echo "🔗 For more information, see README.md"