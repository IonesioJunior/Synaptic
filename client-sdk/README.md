# WebSocket Server Go Client SDK

A high-performance, concurrent Go SDK for interacting with the GenericWSServer WebSocket server. This SDK provides secure authentication, message handling, automatic reconnection, and flexible message processing capabilities.

## Features

- **Ed25519 Authentication**: Secure challenge-response authentication with Ed25519 signatures
- **Automatic Reconnection**: Smart reconnection with exponential backoff and jitter
- **Concurrent Message Processing**: Worker pool pattern for efficient message handling
- **Message Signing & Verification**: Built-in support for message signatures
- **Health Check Management**: Automatic ping/pong handling
- **Flexible Message Handlers**: Multiple handler patterns (async, filtered, chained)
- **Type-Safe Operations**: Strongly typed message structures
- **Metrics & Monitoring**: Built-in metrics collection
- **Thread-Safe**: Designed for concurrent use

## Installation

```bash
go get github.com/genericwsserver/client-sdk
```

## Quick Start

```go
package main

import (
    "fmt"
    "log"
    
    client "github.com/genericwsserver/client-sdk"
    "github.com/genericwsserver/client-sdk/types"
)

func main() {
    // Create client configuration
    config := &client.Config{
        ServerURL:     "https://your-server.com",
        UserID:        "user123",
        Username:      "John Doe",
        AutoReconnect: true,
        Workers:       10,
        Debug:         true,
    }
    
    // Create new client
    c, err := client.NewClient(config)
    if err != nil {
        log.Fatal(err)
    }
    defer c.Disconnect()
    
    // Add message handler
    c.AddMessageHandlerFunc(func(msg *types.Message) error {
        fmt.Printf("Received message from %s: %s\n", 
            msg.Header.From, msg.Body.Content)
        return nil
    })
    
    // Set connection callbacks
    c.OnConnect(func() {
        fmt.Println("Connected to server!")
    })
    
    c.OnDisconnect(func(err error) {
        fmt.Printf("Disconnected: %v\n", err)
    })
    
    // Connect to server
    if err := c.Connect(); err != nil {
        log.Fatal(err)
    }
    
    // Send a message
    err = c.SendMessage("user456", "Hello, World!", true)
    if err != nil {
        log.Printf("Failed to send message: %v", err)
    }
    
    // Broadcast a message
    err = c.Broadcast("Hello everyone!")
    if err != nil {
        log.Printf("Failed to broadcast: %v", err)
    }
    
    // Keep the program running
    select {}
}
```

## Configuration Options

```go
type Config struct {
    ServerURL         string        // WebSocket server URL (required)
    UserID            string        // Unique user identifier (required)
    Username          string        // Display name (required)
    PrivateKey        string        // Base64-encoded Ed25519 private key (optional)
    AutoReconnect     bool          // Enable automatic reconnection (default: false)
    MaxReconnectWait  time.Duration // Maximum reconnection delay (default: 2 minutes)
    MessageBufferSize int           // Message channel buffer size (default: 256)
    Workers           int           // Number of worker goroutines (default: 10)
    Debug             bool          // Enable debug logging (default: false)
}
```

## Authentication

The SDK supports two authentication modes:

### Automatic Key Generation

```go
config := &client.Config{
    ServerURL: "https://server.com",
    UserID:    "user123",
    Username:  "John Doe",
}
c, _ := client.NewClient(config)
```

### Using Existing Keys

```go
import "github.com/genericwsserver/client-sdk/auth"

// Load existing private key
privateKey := "base64-encoded-private-key"

config := &client.Config{
    ServerURL:  "https://server.com",
    UserID:     "user123",
    Username:   "John Doe",
    PrivateKey: privateKey,
}
c, _ := client.NewClient(config)
```

## Message Handling

### Simple Handler

```go
c.AddMessageHandlerFunc(func(msg *types.Message) error {
    fmt.Printf("Message: %s\n", msg.Body.Content)
    return nil
})
```

### Structured Handler

```go
type MyHandler struct{}

func (h *MyHandler) HandleMessage(msg *types.Message) error {
    // Process message
    return nil
}

c.AddMessageHandler(&MyHandler{})
```

### Channel-Based Processing

```go
receiveChan := c.GetReceiveChannel()
errorChan := c.GetErrorChannel()

go func() {
    for {
        select {
        case msg := <-receiveChan:
            // Process message
            fmt.Printf("Received: %s\n", msg.Body.Content)
        case err := <-errorChan:
            // Handle error
            log.Printf("Error: %v\n", err)
        }
    }
}()
```

## Advanced Features

### Message Signatures

```go
// Send signed message
err := c.SendMessage("recipient", "Secure message", true)

// Verify received message signature
c.AddMessageHandlerFunc(func(msg *types.Message) error {
    if msg.Header.Signature != "" {
        valid, err := c.VerifyMessageSignature(msg)
        if err != nil {
            return err
        }
        if !valid {
            return fmt.Errorf("invalid signature")
        }
    }
    return nil
})
```

### Custom Message Types

```go
import "github.com/genericwsserver/client-sdk/extensions"

// Define custom message type
type GameMessage struct {
    types.BaseExtendedMessage
    Action string `json:"action"`
    Score  int    `json:"score"`
}

// Create message router
router := extensions.NewMessageRouter()

// Register custom type
factory := extensions.NewDefaultMessageFactory()
factory.RegisterType("game", &GameMessage{})
router.SetFactory(factory)

// Add typed handler
router.RegisterHandler("game", &GameHandler{})

// Use with client
c.AddMessageHandler(router)
```

### Filtered Message Handling

```go
import "github.com/genericwsserver/client-sdk/extensions"

// Only handle messages from specific users
filter := func(msg *types.Message) bool {
    return msg.Header.From == "admin"
}

handler := extensions.NewFilteredHandler(filter, 
    types.MessageHandlerFunc(func(msg *types.Message) error {
        fmt.Printf("Admin message: %s\n", msg.Body.Content)
        return nil
    }))

c.AddMessageHandler(handler)
```

### Async Message Processing

```go
import "github.com/genericwsserver/client-sdk/extensions"

// Process messages asynchronously
asyncHandler := extensions.NewAsyncHandler(
    types.MessageHandlerFunc(func(msg *types.Message) error {
        // Heavy processing
        time.Sleep(1 * time.Second)
        return nil
    }),
    100,  // Queue size
    5,    // Workers
)

c.AddMessageHandler(asyncHandler)
defer asyncHandler.Stop()
```

## Monitoring

```go
// Get metrics
sent, received, reconnects, errors := c.GetMetrics()
fmt.Printf("Sent: %d, Received: %d, Reconnects: %d, Errors: %d\n",
    sent, received, reconnects, errors)

// Check connection state
if c.IsConnected() {
    fmt.Println("Connected")
}

state := c.GetState()
fmt.Printf("Current state: %s\n", state)
```

## Error Handling

```go
// Connection errors
if err := c.Connect(); err != nil {
    switch {
    case strings.Contains(err.Error(), "register"):
        // Registration failed
    case strings.Contains(err.Error(), "login"):
        // Authentication failed
    case strings.Contains(err.Error(), "WebSocket"):
        // Connection failed
    }
}

// Send errors
if err := c.SendMessage("user", "msg", false); err != nil {
    if errors.Is(err, context.DeadlineExceeded) {
        // Timeout
    }
}
```

## Concurrency Considerations

The SDK is designed to be thread-safe and uses several concurrency patterns:

- **Worker Pool**: Limits concurrent message processing
- **Channel Buffering**: Prevents blocking on message operations
- **Context Cancellation**: Graceful shutdown of goroutines
- **Atomic Operations**: Lock-free state management where possible
- **Read-Write Locks**: Optimized for read-heavy operations

## Best Practices

1. **Always defer Disconnect()**
   ```go
   c, _ := client.NewClient(config)
   defer c.Disconnect()
   ```

2. **Handle errors in message handlers**
   ```go
   c.AddMessageHandlerFunc(func(msg *types.Message) error {
       if err := processMessage(msg); err != nil {
           // Log error but don't crash
           log.Printf("Processing error: %v", err)
           return nil // Return nil to continue processing
       }
       return nil
   })
   ```

3. **Use appropriate buffer sizes**
   ```go
   config.MessageBufferSize = 1000 // For high-volume applications
   config.Workers = 20            // Increase workers for CPU-intensive processing
   ```

4. **Monitor connection state**
   ```go
   c.OnDisconnect(func(err error) {
       // Alert monitoring system
       metrics.RecordDisconnection()
   })
   ```

5. **Implement message verification for sensitive operations**
   ```go
   if !msg.Header.Signature.Valid() {
       return fmt.Errorf("unsigned message for sensitive operation")
   }
   ```

## Testing

Run tests:
```bash
go test ./...
```

Run benchmarks:
```bash
go test -bench=. ./...
```

## License

MIT License

## Contributing

Contributions are welcome! Please ensure:
- All tests pass
- Code follows Go conventions
- New features include tests
- Documentation is updated