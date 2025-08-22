package customhandlers

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"websocketserver/ws"
)

type HelloHandler struct{}

func (h *HelloHandler) Handle(ctx context.Context, server *ws.Server, sender string, params json.RawMessage) (interface{}, error) {
	var input struct {
		Name string `json:"name"`
	}

	if len(params) > 0 {
		if err := json.Unmarshal(params, &input); err != nil {
			return nil, fmt.Errorf("invalid parameters: %w", err)
		}
	}

	greeting := "Hello"
	if input.Name != "" {
		greeting = fmt.Sprintf("Hello, %s", input.Name)
	}

	connectedUsers := server.GetConnectedUsers()

	response := map[string]interface{}{
		"greeting":        greeting,
		"sender":          sender,
		"timestamp":       time.Now().Unix(),
		"connected_users": len(connectedUsers),
		"server_time":     time.Now().Format(time.RFC3339),
	}

	return response, nil
}

func init() {
	Register(
		"hello",
		func() ws.ServerMessageHandler { return &HelloHandler{} },
		"Greeting handler that says hello and provides server info",
	)
}
