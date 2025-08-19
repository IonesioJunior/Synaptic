# Server Messages Example

This example demonstrates how to use the WebSocket server's **Server Message** feature with custom handlers. Server messages allow clients to send commands directly to the server for processing, enabling rich server-side functionality beyond simple message routing.

## Overview

The Server Message feature provides three distinct message workflows:

1. **Direct Messages** - Route encrypted messages to specific users
2. **Broadcast Messages** - Route messages to all connected users  
3. **Server Messages** - Process commands on the server with custom handlers ⭐ **(This Example)**

## Architecture

```
Client ─[Server Message]→ WebSocket Server ─[Custom Handler]→ Response
       ←[Direct Message]─                  ←[Processing]──┘
```

### Key Features

- **Extensible Handler System**: Register custom command handlers
- **Ed25519 Signature Verification**: All server messages must be properly signed
- **Async Processing**: Handlers run in goroutines with timeout protection
- **Request/Response Pattern**: Each command gets a structured response
- **Built-in Commands**: ping, echo, server_info, user_count, list_commands

## Files Structure

```
server-messages/
├── server/
│   └── main.go          # Server with custom handlers
├── client/
│   └── main.go          # Client demonstrating server messages
└── README.md            # This file
```

## Running the Example

### 1. Start the Server

```bash
cd server-messages/server
go run main.go
```

The server will:
- Start on `localhost:8080` (HTTP) or `:8443` (HTTPS if certificates exist)
- Register 4 custom handlers: `system_status`, `list_users`, `math`, `echo_delayed`
- Display available handlers on startup

### 2. Run the Client

```bash
cd server-messages/client
go run main.go
```

The client will:
- Show example message structures
- Attempt to connect to the server
- Provide an interactive command interface if connected

## Custom Handlers Included

### 1. System Status Handler
**Command**: `system_status`
**Purpose**: Returns server uptime and health information

```json
{
  "command": "system_status",
  "request_id": "status-001"
}
```

**Response**:
```json
{
  "success": true,
  "result": {
    "status": "healthy",
    "uptime_seconds": 3600,
    "uptime_human": "1h0m0s",
    "sender": "user123",
    "timestamp": 1704067200
  }
}
```

### 2. Math Handler
**Command**: `math`
**Purpose**: Performs basic mathematical operations

```json
{
  "command": "math",
  "params": {
    "operation": "add",
    "a": 10.5,
    "b": 5.3
  },
  "request_id": "math-001"
}
```

**Response**:
```json
{
  "success": true,
  "result": {
    "operation": "add",
    "a": 10.5,
    "b": 5.3,
    "result": 15.8
  }
}
```

### 3. Delayed Echo Handler
**Command**: `echo_delayed`
**Purpose**: Demonstrates async processing with configurable delay

```json
{
  "command": "echo_delayed",
  "params": {
    "message": "Hello World",
    "delay_ms": 1000
  },
  "request_id": "echo-001"
}
```

### 4. User List Handler
**Command**: `list_users`
**Purpose**: Returns connected users (simplified example)

## Message Format

Server messages use the following structure:

```json
{
  "header": {
    "from": "user_id",
    "to": "server",
    "message_type": "server",
    "timestamp": "2024-01-15T10:30:00Z",
    "signature": "base64_ed25519_signature"
  },
  "body": {
    "content": "{\"command\":\"ping\",\"request_id\":\"req-123\"}"
  }
}
```

### Signature Requirements

- Server messages **MUST** include a valid Ed25519 signature
- The signature covers the entire `body.content` field
- Use the sender's private key to sign the JSON command string
- Invalid or missing signatures result in error responses

## Creating Custom Handlers

Implement the `ServerMessageHandler` interface:

```go
type ServerMessageHandler interface {
    Handle(ctx context.Context, server *Server, sender string, params json.RawMessage) (response interface{}, err error)
}
```

### Example Custom Handler

```go
type WeatherHandler struct{}

func (h *WeatherHandler) Handle(ctx context.Context, server *Server, sender string, params json.RawMessage) (interface{}, error) {
    var request struct {
        City string `json:"city"`
    }
    
    if err := json.Unmarshal(params, &request); err != nil {
        return nil, fmt.Errorf("invalid parameters: %w", err)
    }
    
    // Your custom logic here
    weather := getWeatherForCity(request.City)
    
    return map[string]interface{}{
        "city": request.City,
        "weather": weather,
        "timestamp": time.Now().Unix(),
    }, nil
}

// Register the handler
server.RegisterServerHandler("weather", &WeatherHandler{})
```

## Security Considerations

1. **Signature Verification**: Always verify Ed25519 signatures
2. **Input Validation**: Validate and sanitize all parameters
3. **Timeout Protection**: Handlers run with 30-second timeout
4. **Error Handling**: Implement proper error responses
5. **Access Control**: Consider implementing permission levels for sensitive commands

## Interactive Commands

When connected to a real server, the client supports:

- `ping` - Test server connectivity
- `echo <text>` - Echo back text
- `info` - Get server information  
- `count` - Get connected user count
- `status` - Get system status (custom handler)
- `math <op> <a> <b>` - Perform math operation (custom handler)
- `delay <text> <ms>` - Echo with delay (custom handler)
- `direct <user> <message>` - Send direct message to user
- `quit` - Exit client

## Error Handling

Server messages can fail for various reasons:

### Common Error Responses

```json
{
  "success": false,
  "error": "Server messages must be signed",
  "request_id": "req-123"
}
```

```json
{
  "success": false,
  "error": "Unknown command: invalid_command",
  "request_id": "req-124"
}
```

```json
{
  "success": false,
  "error": "Invalid signature",
  "request_id": "req-125"
}
```

## Development Tips

1. **Testing**: Use the built-in `ping` and `echo` commands for testing
2. **Debugging**: Check server logs for detailed error information
3. **Performance**: Handlers should complete quickly or use async patterns
4. **Monitoring**: Log all server message attempts for security auditing

## Production Considerations

- Use proper TLS certificates (not self-signed)
- Implement rate limiting for server messages
- Add authentication/authorization for sensitive commands
- Monitor handler performance and errors
- Consider handler versioning for API evolution

## Next Steps

1. Study the custom handler implementations in `server/main.go`
2. Experiment with the interactive client
3. Create your own custom handlers for your use case
4. Integrate server messages into your application workflow

This example provides a foundation for building rich server-side functionality in your WebSocket applications!