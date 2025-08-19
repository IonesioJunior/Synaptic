# Environment Variable Setup for WebSocket Clients

This guide explains how to configure WebSocket clients using environment variables for automated deployment with persistent identities.

## Overview

The WebSocket client SDK now supports full configuration via environment variables, eliminating the need for interactive input. This is especially useful for:
- Docker deployments
- CI/CD pipelines
- Automated testing
- Multi-client setups

## Environment Variables

### Required Variables

- `WS_USER_ID` - Unique identifier for the client (required)
- `WS_USERNAME` - Display name for the client (optional, defaults to user ID)

### Optional Variables

- `WS_SERVER_URL` - WebSocket server URL (default: `https://localhost:443`)
- `WS_PRIVATE_KEY` - Base64-encoded Ed25519 private key for persistent identity
- `INSECURE_TLS` - Set to `true` to skip TLS certificate validation (development only)
- `DEBUG` - Set to `true` to enable debug logging
- `AUTO_MODE` - Set to `true` to run in automated mode (sends periodic messages)
- `AUTO_ANNOUNCE` - Set to `true` to announce presence on connect

## Key Persistence

### First Run - Generate Keys

When you run a client without `WS_PRIVATE_KEY`, it will generate a new key pair:

```bash
docker run --rm -e WS_USER_ID=alice -e WS_USERNAME="Alice Smith" websocket-client:latest
```

The client will output:
```
Generated new key pair for alice
Private key (save this): <base64-encoded-private-key>
Public key: <base64-encoded-public-key>
To reuse this identity, set WS_PRIVATE_KEY environment variable
```

### Subsequent Runs - Use Existing Keys

Save the private key and use it in future runs:

```bash
export WS_PRIVATE_KEY="<base64-encoded-private-key-from-above>"
docker run --rm \
  -e WS_USER_ID=alice \
  -e WS_USERNAME="Alice Smith" \
  -e WS_PRIVATE_KEY="$WS_PRIVATE_KEY" \
  websocket-client:latest
```

## Docker Compose Setup

### 1. Create `.env` File

Copy `.env.example` to `.env`:

```bash
cp .env.example .env
```

### 2. Generate Keys (Option A - Manual)

Run each client once to generate keys:

```bash
# Start only Alice to get her key
docker-compose up client-alice

# Check logs for the private key
docker logs ws-client-alice | grep "Private key"

# Add the key to .env file
echo "ALICE_PRIVATE_KEY=<key-from-logs>" >> .env
```

### 3. Generate Keys (Option B - Automated)

Use the provided script to generate all keys:

```bash
./scripts/generate-keys.sh
```

This script will:
- Build the client Docker image
- Generate Ed25519 keys for all clients
- Save them to `.env` file
- Generate JWT secret if needed

### 4. Start Services

With keys configured in `.env`:

```bash
docker-compose up
```

All clients will now use their persistent identities.

## Example .env File

```env
# Server Configuration
JWT_SECRET=your-secret-jwt-key-minimum-16-chars

# Client Private Keys (Ed25519, Base64-encoded)
ALICE_PRIVATE_KEY=mravLKuOinZfSt5JH6yMy39/Y4n5ChsW0v+r6IoXqM3LRoh/4PwIMaTrEclt+SE7bpdeEBKHQ2i6uTcgNiUzGQ==
BOB_PRIVATE_KEY=xyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMN==
CHARLIE_PRIVATE_KEY=abcDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQR==
BOT_PRIVATE_KEY=123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGH==
```

## Programmatic Usage

### Go Example

```go
import (
    "os"
    client "github.com/genericwsserver/client-sdk"
)

func main() {
    config := &client.Config{
        ServerURL:   os.Getenv("WS_SERVER_URL"),
        UserID:      os.Getenv("WS_USER_ID"),
        Username:    os.Getenv("WS_USERNAME"),
        PrivateKey:  os.Getenv("WS_PRIVATE_KEY"),
        InsecureTLS: os.Getenv("INSECURE_TLS") == "true",
        Debug:       os.Getenv("DEBUG") == "true",
    }
    
    c, err := client.NewClient(config)
    // ...
}
```

### Shell Script Example

```bash
#!/bin/bash

# Export configuration
export WS_USER_ID="bot"
export WS_USERNAME="Automation Bot"
export WS_PRIVATE_KEY="your-base64-key-here"
export WS_SERVER_URL="https://websocket-server:443"
export INSECURE_TLS="true"
export AUTO_MODE="true"

# Run the client
./simple-env-client
```

## Security Considerations

1. **Private Key Storage**: Never commit private keys to version control. Use secrets management tools in production.

2. **TLS Certificates**: Only use `INSECURE_TLS=true` in development. Always use valid certificates in production.

3. **Environment Variable Security**: 
   - Use Docker secrets for sensitive data in production
   - Restrict access to `.env` files
   - Rotate keys periodically

4. **Key Generation**: Generate keys in a secure environment and distribute them securely to clients.

## Troubleshooting

### Authentication Failures

If clients fail to authenticate after restart:
1. Ensure the private key in `.env` matches the public key registered with the server
2. Check that the server's database persists between restarts
3. Verify the JWT_SECRET is consistent

### Key Generation Issues

If the generate-keys script fails:
1. Ensure Docker is running
2. Build the client image manually first: `docker build -t websocket-client:latest ./client-sdk`
3. Check for permission issues with `.env` file

### Connection Issues

If clients can't connect:
1. Verify the server is running and healthy: `docker ps`
2. Check server logs: `docker logs ws-server`
3. Ensure network connectivity: `docker network ls`
4. Verify environment variables are set correctly: `docker-compose config`

## Best Practices

1. **Development**: Use `.env` files with test keys
2. **Staging**: Use environment-specific `.env` files, not committed to git
3. **Production**: Use proper secrets management (Kubernetes secrets, AWS Secrets Manager, etc.)
4. **CI/CD**: Generate temporary keys for testing, don't reuse production keys
5. **Monitoring**: Log client connections but never log private keys

## Advanced Configuration

### Custom Message Handlers

The `simple-env` client supports all the same features as the interactive client, but with environment-based configuration. You can extend it with custom handlers, filters, and processors.

### Auto Mode

When `AUTO_MODE=true`, the client will send periodic messages automatically:
- Sends a broadcast message every 30 seconds
- Useful for testing and monitoring
- Can be combined with `AUTO_ANNOUNCE=true` for initial presence

### Multiple Environments

Use different `.env` files for different environments:

```bash
# Development
docker-compose --env-file .env.dev up

# Testing
docker-compose --env-file .env.test up

# Production
docker-compose --env-file .env.prod up
```