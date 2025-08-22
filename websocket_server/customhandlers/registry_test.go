package customhandlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"

	"websocketserver/auth"
	"websocketserver/ws"

	_ "github.com/mattn/go-sqlite3"
)

type TestHandler struct {
	name string
}

func (h *TestHandler) Handle(ctx context.Context, server *ws.Server, sender string, params json.RawMessage) (interface{}, error) {
	return map[string]string{"handler": h.name}, nil
}

func TestCustomHandlerRegistration(t *testing.T) {
	// Create a test database
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}
	defer db.Close()

	// Create auth service and server
	authService := auth.NewService(db, "")
	server := ws.NewServer(db, authService, 5.0, 10, nil)

	// Clear existing registry for test
	registry = make([]HandlerRegistration, 0)

	// Register test handlers
	Register("test1", func() ws.ServerMessageHandler { return &TestHandler{name: "test1"} }, "Test handler 1")
	Register("test2", func() ws.ServerMessageHandler { return &TestHandler{name: "test2"} }, "Test handler 2")

	// Verify registration count
	handlers := GetRegisteredHandlers()
	if len(handlers) != 2 {
		t.Errorf("Expected 2 registered handlers, got %d", len(handlers))
	}

	// Register all handlers with the server
	err = RegisterAll(server)
	if err != nil {
		t.Errorf("Failed to register handlers with server: %v", err)
	}

	// Try to register duplicate (should fail)
	err = RegisterAll(server)
	if err == nil {
		t.Error("Expected error when registering duplicate handlers")
	}
}

func TestHelloHandler(t *testing.T) {
	// Create a test database
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}
	defer db.Close()

	// Create auth service and server
	authService := auth.NewService(db, "")
	server := ws.NewServer(db, authService, 5.0, 10, nil)

	// Create and test the hello handler
	handler := &HelloHandler{}

	// Test with name parameter
	params := json.RawMessage(`{"name": "Alice"}`)
	ctx := context.Background()

	response, err := handler.Handle(ctx, server, "test_user", params)
	if err != nil {
		t.Errorf("Handler returned error: %v", err)
	}

	respMap, ok := response.(map[string]interface{})
	if !ok {
		t.Error("Response is not a map")
	}

	if greeting, ok := respMap["greeting"].(string); !ok || greeting != "Hello, Alice" {
		t.Errorf("Expected greeting 'Hello, Alice', got '%v'", respMap["greeting"])
	}

	// Test without parameters
	response, err = handler.Handle(ctx, server, "test_user", nil)
	if err != nil {
		t.Errorf("Handler returned error: %v", err)
	}

	respMap, ok = response.(map[string]interface{})
	if !ok {
		t.Error("Response is not a map")
	}

	if greeting, ok := respMap["greeting"].(string); !ok || greeting != "Hello" {
		t.Errorf("Expected greeting 'Hello', got '%v'", respMap["greeting"])
	}
}
