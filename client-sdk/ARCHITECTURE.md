# Client SDK Architecture

## Overview

This Go SDK provides a robust, concurrent, and feature-rich client library for interacting with the GenericWSServer WebSocket server. The SDK has been designed following Go best practices with a focus on concurrency, performance, and extensibility.

## Core Design Principles

1. **Concurrency First**: Built with goroutines, channels, and sync primitives for optimal concurrent operation
2. **Thread Safety**: All public APIs are thread-safe using mutexes and atomic operations
3. **Graceful Degradation**: Automatic reconnection with exponential backoff
4. **Zero Dependencies**: Minimal external dependencies (only gorilla/websocket, jwt, and crypto)
5. **Extensibility**: Plugin-style message handlers and flexible message routing

## Architecture Components

### 1. Authentication Layer (`/auth`)

- **Ed25519 Cryptography**: Public key infrastructure for secure authentication
- **Challenge-Response Protocol**: Prevents replay attacks
- **JWT Token Management**: Automatic token refresh before expiration
- **Key Management**: Support for both generated and imported keys

### 2. Client Core (`/client.go`, `/client_internal.go`)

#### Connection Management
- WebSocket connection with automatic protocol upgrade (http→ws, https→wss)
- State machine: Disconnected → Connecting → Connected → Reconnecting
- Atomic state transitions for thread safety

#### Concurrency Patterns
- **Read/Write Pumps**: Separate goroutines for reading and writing
- **Worker Pool**: Configurable pool for parallel message processing
- **Channel-Based Communication**: Buffered channels prevent blocking
- **Context Cancellation**: Clean shutdown of all goroutines

#### Health Monitoring
- Automatic ping/pong handling (54s ping interval, 60s pong timeout)
- Connection state tracking
- Metrics collection (messages sent/received, reconnects, errors)

### 3. Message Types (`/types`)

```go
Message
├── MessageHeader
│   ├── From (sender ID)
│   ├── To (recipient/broadcast)
│   ├── IsBroadcast
│   ├── Timestamp
│   └── Signature (optional Ed25519)
└── MessageBody
    └── Content (string)
```

### 4. Extensions (`/extensions`)

#### Message Router
- Type-based message routing
- Factory pattern for custom message types
- Support for extended message formats

#### Handler Patterns
- **ChainedHandler**: Sequential processing through multiple handlers
- **FilteredHandler**: Conditional message processing
- **AsyncHandler**: Queue-based asynchronous processing with workers

## Concurrency Architecture

### Thread Safety Mechanisms

1. **Connection State**: `atomic.Int32` for lock-free state management
2. **Handler Registry**: `sync.RWMutex` optimized for read-heavy access
3. **Message Channels**: Buffered channels with configurable capacity
4. **Worker Pool**: Semaphore pattern using buffered channel

### Goroutine Management

```
Main Thread
├── Read Pump (goroutine)
│   ├── Reads WebSocket messages
│   ├── Handles pong responses
│   └── Dispatches to handlers
├── Write Pump (goroutine)
│   ├── Sends queued messages
│   ├── Sends periodic pings
│   └── Manages write deadlines
└── Worker Pool (N goroutines)
    └── Process messages concurrently
```

### Channel Architecture

- **Send Channel**: Outgoing messages queue (default: 256 buffer)
- **Receive Channel**: Incoming messages for external processing
- **Error Channel**: Non-blocking error reporting
- **Worker Pool Channel**: Limits concurrent processing

## Performance Characteristics

Based on benchmarks:

- **Message Processing**: ~102ns per message (1 allocation)
- **Concurrent Processing**: ~435ns per message (2 allocations)
- **Ed25519 Signing**: ~20μs per operation
- **Ed25519 Verification**: ~47μs per operation

## Error Handling

1. **Non-Blocking Errors**: Error channel for async error reporting
2. **Graceful Degradation**: Automatic reconnection on connection loss
3. **Panic Recovery**: Worker goroutines recover from panics
4. **Timeout Protection**: All network operations have timeouts

## Security Features

1. **Ed25519 Signatures**: Message authentication and non-repudiation
2. **Challenge-Response Auth**: Prevents replay attacks
3. **JWT Validation**: Secure session management
4. **TLS Support**: Automatic HTTPS/WSS upgrade

## Best Practices Implementation

### Resource Management
- Proper cleanup with `defer` statements
- Context cancellation for goroutine lifecycle
- Channel closing to prevent goroutine leaks

### Synchronization
- Minimal lock contention with fine-grained locking
- Read-write locks for read-heavy operations
- Atomic operations where possible

### Error Propagation
- Errors returned from public APIs
- Error channel for async operations
- Detailed error wrapping with context

## Testing Strategy

### Unit Tests
- Component isolation testing
- Concurrent operation testing
- State transition testing
- Mock-free testing where possible

### Integration Tests
- Multi-client scenarios
- Reconnection testing
- Broadcast verification
- Stress testing with concurrent clients

### Benchmarks
- Message processing performance
- Concurrent operation overhead
- Cryptographic operation costs

## Usage Patterns

### Simple Usage
```go
client → Connect → Add Handlers → Send/Receive → Disconnect
```

### Advanced Usage
```go
client → Custom Factory → Message Router → Typed Handlers
      → Async Processing → Filtered Handling → Metrics
```

## Extension Points

1. **Custom Message Types**: Implement `ExtendedMessage` interface
2. **Message Handlers**: Implement `MessageHandler` interface
3. **Message Factories**: Implement `MessageFactory` interface
4. **Authentication**: Provide custom Ed25519 keys

## Performance Optimization

1. **Worker Pool**: Prevents goroutine explosion
2. **Channel Buffering**: Reduces blocking on high load
3. **Non-Blocking Sends**: Drops messages instead of blocking
4. **Lazy User Info Caching**: Reduces redundant API calls
5. **Read/Write Separation**: Optimized for concurrent access

## Monitoring & Observability

- Built-in metrics collection
- Connection state visibility
- Error tracking and reporting
- Callback hooks for major events

## Future Considerations

1. **Message Compression**: WebSocket compression support
2. **Binary Protocol**: Alternative to JSON for performance
3. **Circuit Breaker**: Advanced failure handling
4. **Message Persistence**: Local message queue for offline support
5. **Distributed Tracing**: OpenTelemetry integration