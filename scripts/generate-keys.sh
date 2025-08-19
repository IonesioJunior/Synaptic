#!/bin/bash

# Script to generate Ed25519 keys for clients and save them to .env file

set -e

echo "Generating Ed25519 keys for WebSocket clients..."

# Check if .env exists
if [ -f ".env" ]; then
    echo "Found existing .env file. Creating backup at .env.backup"
    cp .env .env.backup
else
    echo "Creating new .env file from template..."
    if [ -f ".env.example" ]; then
        cp .env.example .env
    else
        touch .env
    fi
fi

# Function to generate a key and update .env
generate_key_for_client() {
    local CLIENT_NAME=$1
    local ENV_VAR_NAME=$2
    
    echo "Generating key for $CLIENT_NAME..."
    
    # Build and run a temporary container to generate keys
    docker run --rm websocket-client:latest ./simple-env-client 2>&1 | grep "Private key" | head -1 | awk '{print $NF}' > /tmp/${CLIENT_NAME}_key.txt
    
    if [ -s /tmp/${CLIENT_NAME}_key.txt ]; then
        KEY=$(cat /tmp/${CLIENT_NAME}_key.txt)
        echo "Generated key for $CLIENT_NAME: ${KEY:0:20}..."
        
        # Update or add the key to .env
        if grep -q "^${ENV_VAR_NAME}=" .env; then
            # Update existing key
            sed -i "s|^${ENV_VAR_NAME}=.*|${ENV_VAR_NAME}=${KEY}|" .env
        else
            # Add new key
            echo "${ENV_VAR_NAME}=${KEY}" >> .env
        fi
        
        rm /tmp/${CLIENT_NAME}_key.txt
    else
        echo "Failed to generate key for $CLIENT_NAME"
    fi
}

# Build the client image first
echo "Building client Docker image..."
docker build -t websocket-client:latest ./client-sdk

# Generate keys for each client
generate_key_for_client "Alice" "ALICE_PRIVATE_KEY"
generate_key_for_client "Bob" "BOB_PRIVATE_KEY"
generate_key_for_client "Charlie" "CHARLIE_PRIVATE_KEY"
generate_key_for_client "Bot" "BOT_PRIVATE_KEY"

# Ensure JWT_SECRET is set
if ! grep -q "^JWT_SECRET=" .env || [ -z "$(grep '^JWT_SECRET=' .env | cut -d'=' -f2)" ]; then
    echo "Generating JWT secret..."
    JWT_SECRET=$(openssl rand -base64 32)
    if grep -q "^JWT_SECRET=" .env; then
        sed -i "s|^JWT_SECRET=.*|JWT_SECRET=${JWT_SECRET}|" .env
    else
        echo "JWT_SECRET=${JWT_SECRET}" >> .env
    fi
fi

echo ""
echo "Keys generated and saved to .env file!"
echo "You can now run 'docker-compose up' to start the services with persistent identities."
echo ""
echo "To view the keys:"
echo "  cat .env | grep _PRIVATE_KEY"