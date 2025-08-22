#!/bin/bash

# Script to generate self-signed SSL certificates for development
# DO NOT use these certificates in production!

set -e

echo "🔐 Generating self-signed SSL certificates for development..."

# Check if certificates already exist
if [ -f "server.crt" ] && [ -f "server.key" ]; then
    echo "⚠️  Certificates already exist. Remove them first if you want to regenerate."
    echo "   Run: rm server.crt server.key"
    exit 1
fi

# Generate private key and certificate
openssl req -x509 \
    -newkey rsa:4096 \
    -keyout server.key \
    -out server.crt \
    -days 365 \
    -nodes \
    -subj "/C=US/ST=State/L=City/O=Development/CN=localhost" \
    -addext "subjectAltName = DNS:localhost,DNS:ws-server,DNS:websocket-server,IP:127.0.0.1,IP:::1"

# Set appropriate permissions
chmod 600 server.key
chmod 644 server.crt

echo "✅ Certificates generated successfully!"
echo ""
echo "📁 Files created:"
echo "   - server.crt (Certificate)"
echo "   - server.key (Private Key)"
echo ""
echo "⚠️  IMPORTANT:"
echo "   - These are self-signed certificates for DEVELOPMENT ONLY"
echo "   - Never commit these files to version control"
echo "   - For production, use proper certificates from a CA"
echo "   - These files are already in .gitignore"