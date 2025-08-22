# Custom WebSocket Server Handlers

This directory is designed for adding custom message handlers to the WebSocket server. Any Go files placed here (except those ending in `.template`) will be automatically compiled into the server binary.

## Quick Start

1. **Copy the template**: 
   ```bash
   cp example_handler.go.template my_handler.go
   ```

2. **Modify for your needs**: Edit `my_handler.go` to implement your custom logic

3. **Build the server**: The handler will be automatically included when you build or run the server

## How It Works

The system uses Go's `init()` function for automatic registration:

1. Each handler file calls `Register()` in its `init()` function
2. When the server starts, it imports this package, triggering all `init()` functions
3. The main server calls `RegisterAll()` to activate all custom handlers
4. Your handlers are now available for clients to call

## Writing a Custom Handler

### Basic Structure

```go
package customhandlers

import (
    "context"
    "encoding/json"
    "websocketserver/ws"
)

// 1. Define your handler struct
type MyHandler struct{}

// 2. Implement the Handle method
func (h *MyHandler) Handle(ctx context.Context, server *ws.Server, sender string, params json.RawMessage) (interface{}, error) {
    // Your custom logic here
    return map[string]interface{}{
        "result": "success",
    }, nil
}

// 3. Register in init()
func init() {
    Register(
        "my_command",                                    // Command name
        func() ws.ServerMessageHandler { return &MyHandler{} }, // Factory function
        "Description of what this handler does",         // Description
    )
}
```

### Handler Interface

Your handler must implement the `ServerMessageHandler` interface:

```go
type ServerMessageHandler interface {
    Handle(ctx context.Context, server *ws.Server, sender string, params json.RawMessage) (interface{}, error)
}
```

**Parameters:**
- `ctx`: Context with 30-second timeout for handler execution
- `server`: Reference to the WebSocket server (access to database, clients, etc.)
- `sender`: User ID of the client sending the message
- `params`: Raw JSON parameters from the client

**Returns:**
- `interface{}`: Response data (will be JSON marshaled)
- `error`: Any error encountered (will be sent as error response)

## Advanced Examples

### Database Access

```go
func (h *MyHandler) Handle(ctx context.Context, server *ws.Server, sender string, params json.RawMessage) (interface{}, error) {
    // Access the database through server
    db := server.GetDB() // You may need to add this getter method
    
    var result string
    err := db.QueryRowContext(ctx, "SELECT name FROM users WHERE user_id = ?", sender).Scan(&result)
    if err != nil {
        return nil, fmt.Errorf("database error: %w", err)
    }
    
    return map[string]interface{}{
        "user_name": result,
    }, nil
}
```

### Parsing Complex Parameters

```go
type MyParams struct {
    Action  string   `json:"action"`
    Targets []string `json:"targets"`
    Options map[string]interface{} `json:"options"`
}

func (h *MyHandler) Handle(ctx context.Context, server *ws.Server, sender string, params json.RawMessage) (interface{}, error) {
    var p MyParams
    if err := json.Unmarshal(params, &p); err != nil {
        return nil, fmt.Errorf("invalid parameters: %w", err)
    }
    
    // Use strongly-typed parameters
    for _, target := range p.Targets {
        // Process each target
    }
    
    return map[string]interface{}{
        "processed": len(p.Targets),
    }, nil
}
```

### Broadcasting to Other Clients

```go
func (h *MyHandler) Handle(ctx context.Context, server *ws.Server, sender string, params json.RawMessage) (interface{}, error) {
    // You'll need to add methods to Server to expose client communication
    // This is just an example of what you might do
    
    message := map[string]interface{}{
        "notification": "Something happened",
        "from": sender,
    }
    
    // Hypothetical broadcast method (you'd need to implement this)
    // server.BroadcastToAll(message)
    
    return map[string]interface{}{
        "broadcast": "sent",
    }, nil
}
```

## Client Usage

Once registered, clients can call your custom handler like any built-in command:

```json
{
  "header": {
    "from": "alice",
    "to": "server",
    "message_type": "server",
    "timestamp": "2024-01-10T10:30:00Z",
    "signature": "base64_signature"
  },
  "body": {
    "content": "{\"command\":\"my_command\",\"params\":{\"key\":\"value\"},\"request_id\":\"req-123\"}"
  }
}
```

## Best Practices

1. **Use meaningful command names**: Choose descriptive names that won't conflict with built-in commands
2. **Validate parameters**: Always validate and sanitize input parameters
3. **Handle errors gracefully**: Return clear error messages for debugging
4. **Respect context**: Use the provided context for database queries and long operations
5. **Keep it stateless**: Handlers should not maintain state between calls
6. **Log important events**: Use `log.Printf()` for debugging and monitoring
7. **Test your handlers**: Write unit tests in `*_test.go` files

## Built-in Commands

The following commands are already registered by default:
- `ping`: Health check
- `echo`: Echo back parameters
- `server_info`: Get server information
- `user_count`: Get connected user count
- `list_commands`: List all available commands

## Security Notes

- All server messages must be signed with the client's private key
- The server automatically verifies signatures before calling handlers
- Handlers execute with 30-second timeout
- Panic recovery is automatic - panics won't crash the server

## Troubleshooting

1. **Handler not available**: Check the server logs for registration messages
2. **Compilation errors**: Ensure your handler implements the interface correctly
3. **Duplicate command**: Each command name must be unique
4. **Parameters not working**: Verify JSON marshaling/unmarshaling

## Docker Support

Custom handlers are automatically included when building the Docker image:

```dockerfile
# The Dockerfile already copies all Go files
COPY . .
# And builds everything
RUN go build -o server
```

No additional configuration needed!