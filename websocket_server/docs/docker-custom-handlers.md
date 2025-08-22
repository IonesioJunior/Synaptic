# Using Custom Handlers with Docker

This guide explains how to build a Docker image with your own custom handlers for the WebSocket server.

## Overview

Since Go compiles handlers into the binary at build time, custom handlers need to be included during the Docker build process. This guide shows you how to create your own Docker image that includes your custom handlers.

## Prerequisites

- Docker installed on your system
- Your custom handler Go files ready
- Basic understanding of Docker and Go

## Step-by-Step Guide

### 1. Prepare Your Custom Handlers

Create a directory with your custom handler files. Each handler should follow the pattern shown in the `customhandlers/example_handler.go.template`:

```go
package customhandlers

import (
    "websocketserver/ws"
)

func init() {
    Register("your_command", NewYourHandler, "Description of your handler")
}

func NewYourHandler() ws.ServerMessageHandler {
    return &YourHandler{}
}

type YourHandler struct{}

func (h *YourHandler) Handle(msg ws.ServerMessage, s *ws.Server) error {
    // Your handler implementation
    return nil
}
```

### 2. Directory Structure

Organize your project like this:

```
your-project/
├── Dockerfile.custom     # Your custom Dockerfile
├── my-handlers/         # Your custom handlers directory
│   ├── handler1.go
│   ├── handler2.go
│   └── handler3.go
└── websocket_server/    # Clone or copy of the websocket_server source
```

### 3. Create Your Custom Dockerfile

Use the provided `Dockerfile.custom` as a template. The key part is copying your handlers into the build:

```dockerfile
# Copy YOUR custom handlers into the customhandlers directory
COPY my-handlers/*.go ./customhandlers/
```

### 4. Build Your Custom Image

```bash
# Clone the websocket_server repository (if not already done)
git clone https://github.com/IonesioJunior/Synaptic.git

# Copy your handlers
cp -r my-handlers/* Synaptic/websocket_server/customhandlers/

# Build the Docker image with your custom handlers
docker build -f Dockerfile.custom -t my-websocket-server:custom .
```

### 5. Run Your Custom Image

```bash
# Run with default settings
docker run -p 443:443 my-websocket-server:custom

# Run with custom environment variables
docker run -p 443:443 \
  -e JWT_SECRET="your-secret" \
  -e MESSAGE_RATE_LIMIT="10.0" \
  -v $(pwd)/data:/app/data \
  my-websocket-server:custom
```

## Alternative: Multi-Stage Build Approach

If you want to keep your handlers separate from the main source, you can use a more sophisticated multi-stage build:

```dockerfile
# Dockerfile.multistage
FROM golang:1.21-alpine AS handlers

WORKDIR /handlers
COPY my-handlers/ .

FROM golang:1.21-alpine AS builder

# Install dependencies
RUN apk add --no-cache git gcc musl-dev sqlite-dev

WORKDIR /build

# Clone the repository
RUN git clone https://github.com/IonesioJunior/Synaptic.git . && \
    cd websocket_server

# Copy handlers from previous stage
COPY --from=handlers /handlers/*.go ./websocket_server/customhandlers/

# Build the server
WORKDIR /build/websocket_server
RUN go mod download && \
    CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -o websocket-server .

# ... rest of the Dockerfile remains the same
```

## Docker Compose Example

For production deployments, you might want to use Docker Compose:

```yaml
# docker-compose.yml
version: '3.8'

services:
  websocket-server:
    build:
      context: .
      dockerfile: Dockerfile.custom
    ports:
      - "443:443"
      - "80:80"
    environment:
      - JWT_SECRET=${JWT_SECRET}
      - MESSAGE_RATE_LIMIT=10.0
      - MESSAGE_BURST_LIMIT=20
    volumes:
      - ./data:/app/data
      - ./certs/server.crt:/app/server.crt:ro
      - ./certs/server.key:/app/server.key:ro
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "wget", "--no-verbose", "--tries=1", "--spider", "--no-check-certificate", "https://localhost/health"]
      interval: 30s
      timeout: 3s
      retries: 3
```

## CI/CD Integration

For automated builds, you can create a GitHub Action or GitLab CI pipeline:

```yaml
# .github/workflows/build-custom.yml
name: Build Custom WebSocket Server

on:
  push:
    branches: [ main ]
    paths:
      - 'my-handlers/**'
      - 'Dockerfile.custom'

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    
    - name: Build and push Docker image
      run: |
        docker build -f Dockerfile.custom -t my-websocket-server:${{ github.sha }} .
        # Push to your registry
```

## Testing Your Custom Handlers

After building and running your custom image, test that your handlers are registered:

```bash
# Connect to the WebSocket server and send a test message
wscat -c wss://localhost:443 --no-check

# Send your custom command
> {"command": "your_command", "data": {}}
```

## Troubleshooting

### Handlers Not Registering

1. Check that your handler files are in the `customhandlers` package
2. Ensure the `init()` function calls `Register()`
3. Check Docker build logs for compilation errors

### Build Failures

1. Verify Go module dependencies are correct
2. Ensure handler imports match the websocketserver module path
3. Check that handler implements the `ws.ServerMessageHandler` interface

### Runtime Issues

1. Check container logs: `docker logs <container-id>`
2. Verify environment variables are set correctly
3. Ensure certificates are valid (or use HTTP for testing)

## Best Practices

1. **Version Control**: Keep your custom handlers in a separate repository
2. **Testing**: Write unit tests for your handlers before building the Docker image
3. **Security**: Never hardcode secrets in the Dockerfile; use environment variables
4. **Certificates**: Use proper SSL certificates in production, not self-signed ones
5. **Logging**: Implement proper logging in your handlers for debugging
6. **Error Handling**: Always handle errors gracefully in your custom handlers

## Example Custom Handler

Here's a complete example of a custom handler that you can use as a template:

```go
package customhandlers

import (
    "encoding/json"
    "log"
    "time"
    "websocketserver/ws"
)

func init() {
    Register("echo_time", NewEchoTimeHandler, "Echoes message with timestamp")
}

func NewEchoTimeHandler() ws.ServerMessageHandler {
    return &EchoTimeHandler{}
}

type EchoTimeHandler struct{}

type EchoTimeResponse struct {
    OriginalMessage string    `json:"original_message"`
    Timestamp       time.Time `json:"timestamp"`
    ServerID        string    `json:"server_id"`
}

func (h *EchoTimeHandler) Handle(msg ws.ServerMessage, s *ws.Server) error {
    // Parse the incoming message
    var data map[string]interface{}
    if err := json.Unmarshal(msg.Data, &data); err != nil {
        return err
    }
    
    // Create response
    response := EchoTimeResponse{
        OriginalMessage: string(msg.Data),
        Timestamp:       time.Now(),
        ServerID:        "custom-server-1",
    }
    
    responseData, err := json.Marshal(response)
    if err != nil {
        return err
    }
    
    // Send response back to client
    return s.SendToClient(msg.ClientID, responseData)
}
```

## Conclusion

Building a custom Docker image with your own handlers is straightforward once you understand that handlers are compiled into the Go binary. This approach gives you:

- Complete control over handler functionality
- Type-safe handler implementation
- Optimal performance (no runtime loading overhead)
- Easy deployment via Docker

For questions or issues, please refer to the main README or open an issue in the repository.