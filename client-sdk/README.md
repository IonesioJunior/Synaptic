# WebSocket Client SDK for Go

A high-performance, concurrent Go SDK for secure WebSocket communication with built-in end-to-end encryption, automatic reconnection, and flexible message processing.

## ✨ Features

### Core Capabilities
- **End-to-End Encryption**: Automatic AES-256-GCM + X25519 encryption for direct messages
- **Authentication**: Ed25519 public-key cryptography with challenge-response protocol
- **Auto-Reconnection**: Smart exponential backoff with jitter
- **Concurrent Processing**: Worker pool pattern for efficient message handling
- **Message Signatures**: Built-in Ed25519 signature creation and verification
- **Thread-Safe**: Designed for concurrent use with proper synchronization
- **Zero Dependencies**: Minimal external dependencies
- **Flexible Handlers**: Multiple handler patterns (async, filtered, chained)

### Advanced Features
- **Type-Safe Operations**: Strongly typed message structures
- **Metrics & Monitoring**: Built-in performance metrics
- **Health Management**: Automatic ping/pong handling
- **Channel-Based Processing**: Non-blocking message operations
- **Custom Message Types**: Extensible message format support
- **Environment Configuration**: Full configuration via environment variables

## 📋 Prerequisites

- Go 1.21 or higher
- Access to a compatible WebSocket server

## 🛠️ Installation

```bash
go get github.com/yourusername/websocket-client-sdk
```

## 🚀 Quick Start

### Basic Usage

```go
package main

import (
    "fmt"
    "log"
    
    client "github.com/yourusername/websocket-client-sdk"
    "github.com/yourusername/websocket-client-sdk/types"
)

func main() {
    // Configure client
    config := &client.Config{
        ServerURL:        "https://your-server.com",
        UserID:           "alice",
        Username:         "Alice Smith",
        EncryptionPolicy: client.EncryptionRequired,
        AutoReconnect:    true,
        Workers:          10,
    }
    
    // Create client
    c, err := client.NewClient(config)
    if err != nil {
        log.Fatal(err)
    }
    defer c.Disconnect()
    
    // Add message handler
    c.AddMessageHandlerFunc(func(msg *types.Message) error {
        fmt.Printf("From %s: %s\n", msg.Header.From, msg.Body.Content)
        return nil
    })
    
    // Set callbacks
    c.OnConnect(func() {
        fmt.Println("Connected!")
    })
    
    // Connect
    if err := c.Connect(); err != nil {
        log.Fatal(err)
    }
    
    // Send encrypted direct message
    err = c.SendMessage("bob", "Secret message", true)
    
    // Send public broadcast
    err = c.Broadcast("Hello everyone!")
    
    // Keep running
    select {}
}
```

## ⚙️ Configuration

### Configuration Options

```go
type Config struct {
    // Required
    ServerURL  string // WebSocket server URL
    UserID     string // Unique user identifier
    Username   string // Display name
    
    // Authentication
    PrivateKey string // Base64 Ed25519 private key (optional)
    
    // Encryption
    EncryptionPolicy EncryptionPolicy // Disabled/Preferred/Required
    
    // Connection
    AutoReconnect     bool          // Enable auto-reconnection
    MaxReconnectWait  time.Duration // Max reconnection delay (default: 2m)
    InsecureTLS       bool          // Skip TLS verification (dev only)
    
    // Performance
    MessageBufferSize int // Message channel buffer (default: 256)
    Workers           int // Worker goroutines (default: 10)
    
    // Debugging
    Debug bool // Enable debug logging
}
```

### Environment Variables

Configure clients via environment for automation:

```bash
# Required
export WS_USER_ID="alice"
export WS_USERNAME="Alice Smith"

# Optional
export WS_SERVER_URL="https://server.com:443"
export WS_PRIVATE_KEY="base64_ed25519_private_key"
export INSECURE_TLS="true"        # Development only
export DEBUG="true"                # Enable debug logs
export AUTO_MODE="true"            # Automated messaging
export AUTO_ANNOUNCE="true"        # Announce on connect
```

## 🔐 Authentication & Encryption

### Key Management

#### Automatic Key Generation
```go
// Keys generated automatically if not provided
config := &client.Config{
    ServerURL: "https://server.com",
    UserID:    "alice",
    Username:  "Alice Smith",
}
c, _ := client.NewClient(config)

// Get generated keys
publicKey := c.GetPublicKey()
privateKey := c.GetPrivateKey()
```

#### Using Existing Keys
```go
// Load existing Ed25519 private key
privateKey := "your-base64-private-key"

config := &client.Config{
    ServerURL:  "https://server.com",
    UserID:     "alice",
    Username:   "Alice Smith",
    PrivateKey: privateKey,
}
```

#### Key Derivation
```go
// X25519 keys derived from Ed25519 for encryption
import "github.com/yourusername/websocket-client-sdk/crypto"

// Generate new X25519 keys
x25519Private, x25519Public, err := crypto.GenerateX25519KeyPair()

// Or derive from Ed25519 seed
x25519Private, x25519Public, err := crypto.DeriveX25519FromEd25519Seed(ed25519Seed)
```

### Encryption Policies

```go
// Always encrypt (fails if encryption not possible)
config.EncryptionPolicy = client.EncryptionRequired

// Try to encrypt, fallback to plaintext
config.EncryptionPolicy = client.EncryptionPreferred  

// Never encrypt
config.EncryptionPolicy = client.EncryptionDisabled
```

### Encryption Flow

```
1. Alice sends message to Bob
2. SDK generates random AES-256 key
3. Message encrypted with AES-256-GCM
4. AES key encrypted with Bob's X25519 public key
5. Encrypted message + encrypted key sent to server
6. Server relays (cannot decrypt)
7. Bob's SDK decrypts AES key with private X25519
8. Bob's SDK decrypts message with AES key
```

## 💬 Message Handling

### Handler Patterns

#### Simple Handler
```go
c.AddMessageHandlerFunc(func(msg *types.Message) error {
    fmt.Printf("Message: %s\n", msg.Body.Content)
    return nil
})
```

#### Structured Handler
```go
type MyHandler struct {
    db *Database
}

func (h *MyHandler) HandleMessage(msg *types.Message) error {
    // Process and store message
    return h.db.SaveMessage(msg)
}

c.AddMessageHandler(&MyHandler{db: database})
```

#### Channel-Based Processing
```go
receiveChan := c.GetReceiveChannel()
errorChan := c.GetErrorChannel()

go func() {
    for {
        select {
        case msg := <-receiveChan:
            processMessage(msg)
        case err := <-errorChan:
            log.Printf("Error: %v", err)
        }
    }
}()
```

#### Filtered Handler
```go
import "github.com/yourusername/websocket-client-sdk/extensions"

// Only process messages from admins
filter := func(msg *types.Message) bool {
    return strings.HasPrefix(msg.Header.From, "admin_")
}

handler := extensions.NewFilteredHandler(filter, 
    types.MessageHandlerFunc(func(msg *types.Message) error {
        fmt.Printf("Admin: %s\n", msg.Body.Content)
        return nil
    }))

c.AddMessageHandler(handler)
```

#### Async Handler
```go
// Process messages asynchronously with worker pool
asyncHandler := extensions.NewAsyncHandler(
    types.MessageHandlerFunc(func(msg *types.Message) error {
        // Heavy processing
        time.Sleep(1 * time.Second)
        return processHeavyTask(msg)
    }),
    100,  // Queue size
    5,    // Workers
)

c.AddMessageHandler(asyncHandler)
defer asyncHandler.Stop()
```

#### Chained Handlers
```go
// Sequential processing through multiple handlers
chain := extensions.NewChainedHandler(
    &LoggingHandler{},
    &ValidationHandler{},
    &ProcessingHandler{},
    &StorageHandler{},
)

c.AddMessageHandler(chain)
```

## 📨 Sending Messages

### Direct Messages (Encrypted)
```go
// Send encrypted message with signature
err := c.SendMessage("bob", "Secret message", true)

// Send without signature
err := c.SendMessage("bob", "Message", false)
```

### Broadcast Messages (Public)
```go
// Broadcast to all users (never encrypted)
err := c.Broadcast("Public announcement!")
```

### Server Commands
```go
// Send command to server (must be signed)
command := map[string]interface{}{
    "command": "ping",
    "request_id": "req-123",
}

response, err := c.SendServerCommand(command)
```

### Message Signatures
```go
// Verify received message signature
c.AddMessageHandlerFunc(func(msg *types.Message) error {
    if msg.Header.Signature != "" {
        valid, err := c.VerifyMessageSignature(msg)
        if err != nil {
            return err
        }
        if !valid {
            return fmt.Errorf("invalid signature from %s", msg.Header.From)
        }
    }
    // Process verified message
    return nil
})
```

## 🏗️ Architecture

### Concurrency Model

```
Main Thread
├── Read Pump (goroutine)
│   ├── Reads WebSocket messages
│   ├── Handles pong responses
│   └── Dispatches to handlers
├── Write Pump (goroutine)
│   ├── Sends queued messages
│   ├── Sends periodic pings (54s)
│   └── Manages write deadlines
└── Worker Pool (N goroutines)
    └── Process messages concurrently
```

### Thread Safety

- **Connection State**: `atomic.Int32` for lock-free state
- **Handler Registry**: `sync.RWMutex` for read-heavy access
- **Message Channels**: Buffered channels with configurable capacity
- **Worker Pool**: Semaphore pattern using buffered channel

### Component Structure

```
client-sdk/
├── client.go           # Main client implementation
├── client_internal.go  # Internal helpers
├── auth/              # Authentication & key management
│   ├── auth.go       # Ed25519 & JWT handling
│   └── keys.go       # Key generation/derivation
├── crypto/            # Encryption implementation
│   ├── crypto.go     # X25519 & AES functions
│   └── crypto_test.go
├── types/             # Message types & interfaces
│   ├── message.go    # Core message structures
│   └── handlers.go   # Handler interfaces
├── extensions/        # Advanced features
│   ├── router.go     # Message routing
│   ├── async.go      # Async processing
│   ├── filter.go     # Message filtering
│   └── chain.go      # Handler chaining
└── examples/          # Usage examples
    ├── simple/       # Basic usage
    ├── advanced/     # Advanced features
    └── server-messages/ # Server commands
```

## 🎯 Advanced Features

### Custom Message Types

```go
import "github.com/yourusername/websocket-client-sdk/extensions"

// Define custom message type
type GameMessage struct {
    types.BaseExtendedMessage
    Action   string `json:"action"`
    Position struct {
        X int `json:"x"`
        Y int `json:"y"`
    } `json:"position"`
    Score int `json:"score"`
}

// Create router and factory
router := extensions.NewMessageRouter()
factory := extensions.NewDefaultMessageFactory()

// Register custom type
factory.RegisterType("game", &GameMessage{})
router.SetFactory(factory)

// Add typed handler
router.RegisterHandler("game", &GameHandler{})

// Use with client
c.AddMessageHandler(router)
```

### Message Router

```go
// Route messages by type to different handlers
router := extensions.NewMessageRouter()

router.RegisterHandler("chat", &ChatHandler{})
router.RegisterHandler("notification", &NotificationHandler{})
router.RegisterHandler("system", &SystemHandler{})

c.AddMessageHandler(router)
```

### Metrics & Monitoring

```go
// Get performance metrics
sent, received, reconnects, errors := c.GetMetrics()
fmt.Printf("Sent: %d, Received: %d, Reconnects: %d, Errors: %d\n",
    sent, received, reconnects, errors)

// Check connection state
if c.IsConnected() {
    state := c.GetState() // "connected", "connecting", "disconnected"
    fmt.Printf("State: %s\n", state)
}

// Monitor connection events
c.OnConnect(func() {
    metrics.RecordConnection()
})

c.OnDisconnect(func(err error) {
    metrics.RecordDisconnection(err)
})

c.OnReconnect(func(attempt int) {
    fmt.Printf("Reconnection attempt %d\n", attempt)
})
```

## 🐳 Docker Deployment

### Dockerfile

```dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o client ./examples/simple

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/client .
CMD ["./client"]
```

### Docker Compose

```yaml
version: '3.8'

services:
  client-alice:
    build: .
    container_name: ws-client-alice
    environment:
      - WS_USER_ID=alice
      - WS_USERNAME=Alice Smith
      - WS_PRIVATE_KEY=${ALICE_PRIVATE_KEY}
      - WS_SERVER_URL=https://server:443
      - INSECURE_TLS=true
      - AUTO_ANNOUNCE=true
    networks:
      - wsnet
    stdin_open: true
    tty: true

networks:
  wsnet:
    driver: bridge
```

### Multi-Client Setup

```bash
# Generate keys for all clients
./scripts/generate-keys.sh

# Start multiple clients
docker compose up -d

# Attach to client for interaction
docker attach ws-client-alice

# View logs
docker compose logs -f client-alice
```

## 🧪 Testing

### Running Tests

```bash
# Run all tests
go test ./...

# Run with coverage
go test -cover ./...

# Run specific package tests
go test ./crypto -v
go test ./auth -v

# Run benchmarks
go test -bench=. ./...
```

### Benchmark Results

```
BenchmarkMessageProcessing-8        10000000   102 ns/op   1 allocs/op
BenchmarkConcurrentProcessing-8      2000000   435 ns/op   2 allocs/op
BenchmarkEd25519Sign-8                 50000    20 μs/op
BenchmarkEd25519Verify-8               20000    47 μs/op
BenchmarkX25519Encryption-8            30000    38 μs/op
BenchmarkAESEncryption-8              100000    15 μs/op
```

## 🚀 Examples

### Simple Interactive Client

```go
// examples/simple/main.go
scanner := bufio.NewScanner(os.Stdin)
for scanner.Scan() {
    text := scanner.Text()
    
    if strings.HasPrefix(text, "@") {
        // Direct message: @username message
        parts := strings.SplitN(text[1:], " ", 2)
        c.SendMessage(parts[0], parts[1], true)
    } else if strings.HasPrefix(text, "!") {
        // Broadcast: !message
        c.Broadcast(text[1:])
    }
}
```

### Advanced Client with Metrics

```go
// examples/advanced/main.go
// Periodic metrics reporting
go func() {
    ticker := time.NewTicker(30 * time.Second)
    for range ticker.C {
        sent, received, _, _ := c.GetMetrics()
        fmt.Printf("Stats - Sent: %d, Received: %d\n", sent, received)
    }
}()
```

### Server Message Example

```go
// examples/server-messages/client/main.go
// Send server command
response, err := c.SendServerCommand(map[string]interface{}{
    "command": "system_status",
    "request_id": "status-001",
})

if err == nil {
    fmt.Printf("Server status: %v\n", response)
}
```

## 🔧 Best Practices

### Connection Management
```go
// Always defer disconnect
c, _ := client.NewClient(config)
defer c.Disconnect()

// Handle graceful shutdown
sigChan := make(chan os.Signal, 1)
signal.Notify(sigChan, os.Interrupt)
go func() {
    <-sigChan
    c.Disconnect()
    os.Exit(0)
}()
```

### Error Handling
```go
// Don't let handler errors crash the client
c.AddMessageHandlerFunc(func(msg *types.Message) error {
    if err := riskyOperation(msg); err != nil {
        // Log but continue processing
        log.Printf("Error processing message: %v", err)
        return nil // Return nil to continue
    }
    return nil
})
```

### Performance Tuning
```go
// High-volume configuration
config := &client.Config{
    MessageBufferSize: 1000, // Larger buffer for high volume
    Workers:           20,    // More workers for CPU-intensive tasks
    MaxReconnectWait:  5 * time.Minute,
}
```

### Security
```go
// Always verify signatures for sensitive operations
if !isSignatureValid(msg) {
    return fmt.Errorf("unsigned message for sensitive operation")
}

// Use encryption for sensitive data
config.EncryptionPolicy = client.EncryptionRequired
```

## 🚨 Troubleshooting

### Connection Issues

```go
// Enable debug logging
config.Debug = true

// Check connection state
if !c.IsConnected() {
    state := c.GetState()
    fmt.Printf("Not connected, state: %s\n", state)
}

// Monitor reconnection attempts
c.OnReconnect(func(attempt int) {
    fmt.Printf("Reconnecting... attempt %d\n", attempt)
})
```

### Authentication Failures

```go
if err := c.Connect(); err != nil {
    switch {
    case strings.Contains(err.Error(), "register"):
        // User not registered
    case strings.Contains(err.Error(), "challenge"):
        // Challenge-response failed
    case strings.Contains(err.Error(), "signature"):
        // Invalid signature
    }
}
```

### Message Delivery

```go
// Check for send errors
if err := c.SendMessage("user", "msg", false); err != nil {
    if errors.Is(err, context.DeadlineExceeded) {
        // Timeout - message may not be delivered
    } else if strings.Contains(err.Error(), "not connected") {
        // Client disconnected
    }
}
```

## 📊 Performance Characteristics

- **Message Processing**: ~102ns per message (1 allocation)
- **Concurrent Processing**: ~435ns with worker pool (2 allocations)
- **Ed25519 Operations**: Sign ~20μs, Verify ~47μs
- **X25519 Encryption**: ~38μs per operation
- **AES-256-GCM**: ~15μs per message
- **Memory Usage**: ~50MB for 10,000 concurrent messages
- **Goroutines**: 3 + N workers (configurable)

## 🔒 Security Considerations

### Production Checklist

- [ ] Use valid TLS certificates (not self-signed)
- [ ] Store private keys securely (never in code)
- [ ] Enable encryption for sensitive messages
- [ ] Verify signatures on critical operations
- [ ] Implement message replay protection
- [ ] Regular key rotation
- [ ] Monitor for suspicious activity
- [ ] Rate limit outgoing messages
- [ ] Validate all incoming data

## 📝 License

MIT License - See LICENSE file for details

## 🤝 Contributing

We welcome contributions! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing`)
3. Write tests for new features
4. Ensure all tests pass (`go test ./...`)
5. Commit changes (`git commit -m 'Add amazing feature'`)
6. Push to branch (`git push origin feature/amazing`)
7. Open a Pull Request

## 📚 Resources

- [API Documentation](./docs/api.md)
- [Architecture Details](./ARCHITECTURE.md)
- [Security Guide](./docs/security.md)
- [Migration Guide](./docs/migration.md)
- [Server Repository](https://github.com/yourusername/websocket-server)

## 💡 Support

- Open an issue for bugs or feature requests
- Check closed issues for solutions
- Review the examples directory
- Read the architecture documentation

---

Built with ❤️ in Go for high-performance, secure WebSocket communication