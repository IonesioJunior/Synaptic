package ws

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// ServerMessageHandler defines the interface for handling server messages
type ServerMessageHandler interface {
	// Handle processes a server message command
	// ctx: Context for cancellation and timeout
	// server: Reference to the WebSocket server for accessing resources
	// sender: User ID of the message sender
	// params: Command-specific parameters
	Handle(ctx context.Context, server *Server, sender string, params json.RawMessage) (response interface{}, err error)
}

// ServerMessageRegistry manages registered server message handlers
type ServerMessageRegistry struct {
	handlers map[string]ServerMessageHandler
	mu       sync.RWMutex
}

// NewServerMessageRegistry creates a new handler registry
func NewServerMessageRegistry() *ServerMessageRegistry {
	return &ServerMessageRegistry{
		handlers: make(map[string]ServerMessageHandler),
	}
}

// Register adds a new handler for a specific command
func (r *ServerMessageRegistry) Register(command string, handler ServerMessageHandler) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.handlers[command]; exists {
		return fmt.Errorf("handler for command '%s' already registered", command)
	}

	r.handlers[command] = handler
	return nil
}

// Get retrieves a handler for a specific command
func (r *ServerMessageRegistry) Get(command string) (ServerMessageHandler, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	handler, exists := r.handlers[command]
	return handler, exists
}

// List returns all registered command names
func (r *ServerMessageRegistry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	commands := make([]string, 0, len(r.handlers))
	for cmd := range r.handlers {
		commands = append(commands, cmd)
	}
	return commands
}

// Built-in server message handlers

// PingHandler responds to ping requests
type PingHandler struct{}

func (h *PingHandler) Handle(ctx context.Context, server *Server, sender string, params json.RawMessage) (interface{}, error) {
	return map[string]interface{}{
		"message": "pong",
		"timestamp": time.Now().Unix(),
	}, nil
}

// EchoHandler echoes back the provided parameters
type EchoHandler struct{}

func (h *EchoHandler) Handle(ctx context.Context, server *Server, sender string, params json.RawMessage) (interface{}, error) {
	var data interface{}
	if len(params) > 0 {
		if err := json.Unmarshal(params, &data); err != nil {
			return nil, fmt.Errorf("invalid params: %w", err)
		}
	}
	return map[string]interface{}{
		"echo": data,
		"sender": sender,
	}, nil
}

// ServerInfoHandler returns basic server information
type ServerInfoHandler struct{}

func (h *ServerInfoHandler) Handle(ctx context.Context, server *Server, sender string, params json.RawMessage) (interface{}, error) {
	server.mu.RLock()
	connectedUsers := len(server.clients)
	server.mu.RUnlock()

	return map[string]interface{}{
		"version": "1.0.0",
		"connected_users": connectedUsers,
		"timestamp": time.Now().Unix(),
	}, nil
}

// UserCountHandler returns the number of connected users
type UserCountHandler struct{}

func (h *UserCountHandler) Handle(ctx context.Context, server *Server, sender string, params json.RawMessage) (interface{}, error) {
	server.mu.RLock()
	count := len(server.clients)
	server.mu.RUnlock()

	return map[string]interface{}{
		"count": count,
		"timestamp": time.Now().Unix(),
	}, nil
}

// ListCommandsHandler returns all available server commands
type ListCommandsHandler struct{}

func (h *ListCommandsHandler) Handle(ctx context.Context, server *Server, sender string, params json.RawMessage) (interface{}, error) {
	commands := server.serverHandlers.List()
	return map[string]interface{}{
		"commands": commands,
		"count": len(commands),
	}, nil
}

// RegisterDefaultHandlers registers all built-in handlers
func (r *ServerMessageRegistry) RegisterDefaultHandlers() {
	r.Register("ping", &PingHandler{})
	r.Register("echo", &EchoHandler{})
	r.Register("server_info", &ServerInfoHandler{})
	r.Register("user_count", &UserCountHandler{})
	r.Register("list_commands", &ListCommandsHandler{})
}