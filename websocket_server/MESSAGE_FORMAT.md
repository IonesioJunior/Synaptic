# WebSocket Message Format

## Message Structure

Messages use a header/body architecture with three distinct message types:

```json
{
  "header": {
    "from": "sender_user_id",
    "to": "recipient_user_id",
    "message_type": "direct|broadcast|server",
    "timestamp": "2024-01-15T10:30:00Z",
    "signature": "optional_base64_signature"
  },
  "body": {
    "content": "Your message content here"
  }
}
```

## Examples

### Direct Message
```json
{
  "header": {
    "from": "user123",
    "to": "user456",
    "message_type": "direct",
    "timestamp": "2024-01-15T10:30:00Z",
    "signature": "base64_signature_here"
  },
  "body": {
    "content": "Hello, how are you?"
  }
}
```

### Broadcast Message
```json
{
  "header": {
    "from": "user123",
    "to": "broadcast",
    "message_type": "broadcast",
    "timestamp": "2024-01-15T10:30:00Z"
  },
  "body": {
    "content": "Announcement to all users!"
  }
}
```

### Server Message
```json
{
  "header": {
    "from": "user123",
    "to": "server",
    "message_type": "server",
    "timestamp": "2024-01-15T10:30:00Z",
    "signature": "required_base64_signature"
  },
  "body": {
    "content": "{\"command\":\"ping\",\"request_id\":\"req-123\"}"
  }
}
```

#### Server Message Content Structure
The content field for server messages must be a JSON string containing:
```json
{
  "command": "command_name",
  "params": {
    "param1": "value1",
    "param2": "value2"
  },
  "request_id": "optional_request_id"
}
```

#### Server Response
Server messages receive a response in the following format:
```json
{
  "header": {
    "from": "server",
    "to": "user123",
    "message_type": "direct",
    "timestamp": "2024-01-15T10:30:01Z"
  },
  "body": {
    "content": "{\"success\":true,\"request_id\":\"req-123\",\"result\":{...}}"
  }
}
```

## Field Descriptions

### Header Fields
- `from` (string): Sender's user ID
- `to` (string): Recipient's user ID, "broadcast" for broadcast messages, or "server" for server messages
- `message_type` (string): Type of message - "direct", "broadcast", or "server" (required)
- `is_broadcast` (bool): Deprecated - use message_type instead (kept for backward compatibility)
- `timestamp` (time): Message creation time in ISO 8601 format
- `signature` (string): Base64-encoded Ed25519 signature (optional for direct/broadcast, required for server messages)

### Body Fields
- `content` (string): The actual message text (for server messages, this must be a JSON string)

### System Fields (not sent by clients)
- `id` (int): Auto-generated message identifier (added by server)
- `status` (string): Message delivery status - "pending", "delivered", "verified", or "error" (managed by server)

## Server Messages

### Built-in Commands
The server provides the following built-in commands:

1. **ping** - Health check
   - Params: None
   - Returns: `{"message": "pong", "timestamp": unix_timestamp}`

2. **echo** - Echo back parameters
   - Params: Any JSON object
   - Returns: `{"echo": <your_params>, "sender": "user_id"}`

3. **server_info** - Get server information
   - Params: None
   - Returns: `{"version": "1.0.0", "connected_users": count, "timestamp": unix_timestamp}`

4. **user_count** - Get connected user count
   - Params: None
   - Returns: `{"count": number, "timestamp": unix_timestamp}`

5. **list_commands** - List available commands
   - Params: None
   - Returns: `{"commands": ["cmd1", "cmd2", ...], "count": number}`

### Custom Server Handlers
To register custom server message handlers, implement the `ServerMessageHandler` interface:

```go
type ServerMessageHandler interface {
    Handle(ctx context.Context, server *Server, sender string, params json.RawMessage) (response interface{}, err error)
}

// Register your handler
server.RegisterServerHandler("my_command", &MyCustomHandler{})
```

### Security Notes
- Server messages MUST be signed with the sender's Ed25519 private key
- The signature covers the entire body.content field
- Server messages are NOT stored in the database
- Server messages are processed asynchronously with timeout protection
- Invalid signatures or missing signatures result in error responses