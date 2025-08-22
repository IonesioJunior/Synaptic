# Quick Start: Adding Your First Custom Handler

## 1. Create Your Handler File

Create a new file in this directory (e.g., `my_handler.go`):

```go
package custom_handlers

import (
    "context"
    "encoding/json"
    "websocketserver/ws"
)

type MyHandler struct{}

func (h *MyHandler) Handle(ctx context.Context, server *ws.Server, sender string, params json.RawMessage) (interface{}, error) {
    // Your logic here
    return map[string]interface{}{
        "message": "Hello from my custom handler!",
        "sender": sender,
    }, nil
}

func init() {
    Register(
        "my_command",
        func() ws.ServerMessageHandler { return &MyHandler{} },
        "My custom handler description",
    )
}
```

## 2. Build and Run

```bash
# From websocket_server directory
go build -o server
./server
```

Or with Docker:

```bash
docker build -t my-ws-server .
docker run -p 443:443 -p 80:80 my-ws-server
```

## 3. Test Your Handler

Send a WebSocket message to test:

```json
{
  "header": {
    "from": "alice",
    "to": "server",
    "message_type": "server",
    "timestamp": "2024-01-10T10:30:00Z",
    "signature": "your_signature_here"
  },
  "body": {
    "content": "{\"command\":\"my_command\",\"params\":{},\"request_id\":\"test-123\"}"
  }
}
```

## That's It!

Your handler is now available. The server automatically loads all handlers from this directory at startup.