# Multi-Client Peer Communication Setup

This docker-compose configuration sets up a WebSocket server with three different client peers that can communicate with each other in real-time.

## Architecture

```
                    ┌─────────────────┐
                    │   WS Server     │
                    │  (Port 443/80)  │
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
         ┌────▼────┐    ┌────▼────┐    ┌────▼────┐
         │  Alice  │    │   Bob   │    │ Charlie │
         │ (Simple)│    │(Simple) │    │(Advanced)│
         └─────────┘    └─────────┘    └─────────┘
                             │
                        ┌────▼────┐
                        │   Bot   │
                        │ (Auto)  │
                        └─────────┘
```

## Peer Details

### 1. **Alice** (`client-alice`)
- **User ID**: alice
- **Type**: Simple interactive client
- **Features**: Manual message sending, TTY enabled
- **Use Case**: Interactive chat participant

### 2. **Bob** (`client-bob`)
- **User ID**: bob  
- **Type**: Simple interactive client
- **Features**: Manual message sending, TTY enabled
- **Use Case**: Interactive chat participant

### 3. **Charlie** (`client-charlie`)
- **User ID**: charlie
- **Type**: Advanced client
- **Features**: Automated features, metrics collection
- **Use Case**: Demonstrates advanced SDK capabilities

### 4. **Message Bot** (`message-bot`)
- **User ID**: bot
- **Type**: Automated client
- **Features**: Sends periodic broadcasts
- **Use Case**: System announcements, testing

## Quick Start

### 1. Start All Services
```bash
docker compose up -d
```

### 2. Start Selective Clients
```bash
# Start only Alice and Bob
just docker-compose-up-selective "alice bob"

# Start server and Charlie only
docker compose up -d websocket-server client-charlie
```

### 3. View Logs
```bash
# All services
docker compose logs -f

# Only clients
just docker-compose-logs-clients

# Specific client
docker compose logs -f client-alice
```

### 4. Interact with Clients

#### Attach to Alice's terminal:
```bash
docker attach ws-client-alice
# Or using just:
just docker-attach-client alice
```

#### Send messages:
- **Direct message**: `@bob Hello Bob!`
- **Broadcast**: `!Hello everyone!`
- **Exit**: `/quit`

**Note**: To detach without stopping: Press `Ctrl+P` then `Ctrl+Q`

### 5. Check Active Users
```bash
# Using just command
just docker-active-users

# Or directly
docker exec ws-server wget -qO- http://localhost/active-users | jq
```

## Communication Examples

### Direct Messaging
Alice sends to Bob:
```
# In Alice's terminal
@bob Hey Bob, how are you?
```

Bob replies to Alice:
```
# In Bob's terminal  
@alice I'm good, thanks!
```

### Broadcasting
Charlie broadcasts to all:
```
# Charlie sends
!Team meeting in 5 minutes
```
All connected clients (Alice, Bob, Bot) receive the message.

### Message Verification
Messages can be signed and verified:
- Signed messages show `[VERIFIED]` tag
- Ensures message authenticity

## Advanced Operations

### 1. Scale Clients
```yaml
# Add more clients in docker-compose.yml
client-david:
  image: websocket-client:latest
  container_name: ws-client-david
  environment:
    - WS_USER_ID=david
    - WS_USERNAME=David Wilson
  # ... rest of configuration
```

### 2. Custom Message Bot
Create a custom bot script:
```bash
#!/bin/sh
while true; do
  echo "!System check at $(date)" 
  sleep 60
done | ./simple-client
```

### 3. Performance Testing
Run multiple client instances:
```bash
for i in {1..10}; do
  docker run -d \
    --name client-$i \
    --network genericwsserver_wsnet \
    -e WS_USER_ID=client$i \
    -e WS_USERNAME="Client $i" \
    -e WS_SERVER_URL=https://websocket-server:443 \
    -e INSECURE_TLS=true \
    websocket-client:latest \
    ./advanced-client
done
```

## Network Configuration

The services use a custom bridge network (`wsnet`) with:
- **Subnet**: 172.25.0.0/16
- **Internal DNS**: Service names resolve to container IPs
- **Isolation**: Containers can only communicate within the network

## Security Considerations

1. **TLS/SSL**: Server uses HTTPS with self-signed certificates
2. **InsecureTLS**: Enabled for development (disable in production)
3. **JWT Authentication**: 24-hour token validity
4. **Ed25519 Signatures**: Message authentication support
5. **Rate Limiting**: 10 msg/sec, burst of 20

## Troubleshooting

### Client Can't Connect
```bash
# Check server health
docker compose ps websocket-server

# View server logs
docker compose logs websocket-server
```

### Message Not Delivered
```bash
# Check if recipient is online
just docker-active-users

# Check client logs
docker compose logs client-bob
```

### Clean Restart
```bash
docker compose down
docker compose up -d --force-recreate
```

## Demo Script

Run the automated demo:
```bash
./demo-multi-client.sh
```

This will:
1. Build all images
2. Start the server
3. Launch three clients
4. Start the message bot
5. Show real-time logs

## Monitoring

### Metrics
- Messages sent/received per client
- Connection status
- Error rates

### Health Checks
- Server: HTTP health endpoint
- Clients: Connection state monitoring

## Clean Up

```bash
# Stop all services
docker compose down

# Remove volumes
docker compose down -v

# Remove images
docker compose down --rmi all
```