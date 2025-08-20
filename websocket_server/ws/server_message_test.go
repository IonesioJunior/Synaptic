package ws

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
	"websocketserver/auth"
	"websocketserver/models"

	"github.com/DATA-DOG/go-sqlmock"
)

// TestServerMessageHandler tests the server message handler registration and execution
func TestServerMessageHandler(t *testing.T) {
	// Create a mock database
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock database: %v", err)
	}
	defer db.Close()

	// Create auth service and server
	authService := auth.NewService(db, "")
	server := NewServer(db, authService, 5.0, 10, nil)

	// Test handler registration
	testHandler := &MockServerHandler{
		response: map[string]string{"test": "response"},
	}

	err = server.RegisterServerHandler("test_command", testHandler)
	if err != nil {
		t.Errorf("Failed to register handler: %v", err)
	}

	// Test duplicate registration
	err = server.RegisterServerHandler("test_command", testHandler)
	if err == nil {
		t.Error("Expected error for duplicate handler registration")
	}

	// Test handler retrieval
	handler, exists := server.serverHandlers.Get("test_command")
	if !exists {
		t.Error("Handler not found after registration")
	}
	if handler != testHandler {
		t.Error("Retrieved handler doesn't match registered handler")
	}

	// Test handler execution
	ctx := context.Background()
	params := json.RawMessage(`{"param1": "value1"}`)
	response, err := handler.Handle(ctx, server, "test_user", params)
	if err != nil {
		t.Errorf("Handler execution failed: %v", err)
	}

	respMap, ok := response.(map[string]string)
	if !ok {
		t.Error("Unexpected response type")
	}
	if respMap["test"] != "response" {
		t.Error("Unexpected response content")
	}

	// Test built-in handlers
	builtinCommands := []string{"ping", "echo", "server_info", "user_count", "list_commands"}
	for _, cmd := range builtinCommands {
		_, exists := server.serverHandlers.Get(cmd)
		if !exists {
			t.Errorf("Built-in handler '%s' not registered", cmd)
		}
	}

	// Clean up expectations
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

// TestServerMessageSignatureVerification tests signature verification for server messages
func TestServerMessageSignatureVerification(t *testing.T) {
	// Create a mock database
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock database: %v", err)
	}
	defer db.Close()

	// Generate test keypair
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	// Create server
	authService := auth.NewService(db, "")
	server := NewServer(db, authService, 5.0, 10, nil)

	// Create test message
	serverCmd := models.ServerCommand{
		Command:   "ping",
		RequestID: "test-123",
	}
	cmdJSON, _ := json.Marshal(serverCmd)

	msg := models.Message{
		Header: models.MessageHeader{
			From:        "test_user",
			To:          "server",
			MessageType: models.MessageTypeServer,
			Timestamp:   time.Now(),
		},
		Body: models.MessageBody{
			Content: string(cmdJSON),
		},
	}

	// Test with valid signature
	signature := ed25519.Sign(privateKey, cmdJSON)
	msg.Header.Signature = base64.StdEncoding.EncodeToString(signature)

	// Mock database query for public key
	publicKeyStr := base64.StdEncoding.EncodeToString(publicKey)
	mock.ExpectQuery("SELECT public_key FROM users WHERE user_id = ?").
		WithArgs("test_user").
		WillReturnRows(sqlmock.NewRows([]string{"public_key"}).AddRow(publicKeyStr))

	err = server.verifyServerMessageSignature("test_user", msg)
	if err != nil {
		t.Errorf("Valid signature verification failed: %v", err)
	}

	// Test with invalid signature
	msg.Header.Signature = base64.StdEncoding.EncodeToString([]byte("invalid_signature"))

	mock.ExpectQuery("SELECT public_key FROM users WHERE user_id = ?").
		WithArgs("test_user").
		WillReturnRows(sqlmock.NewRows([]string{"public_key"}).AddRow(publicKeyStr))

	err = server.verifyServerMessageSignature("test_user", msg)
	if err == nil {
		t.Error("Invalid signature should have failed verification")
	}

	// Test with missing user
	mock.ExpectQuery("SELECT public_key FROM users WHERE user_id = ?").
		WithArgs("nonexistent_user").
		WillReturnError(sql.ErrNoRows)

	err = server.verifyServerMessageSignature("nonexistent_user", msg)
	if err == nil {
		t.Error("Verification should fail for non-existent user")
	}

	// Clean up expectations
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

// TestBuiltInHandlers tests the built-in server message handlers
func TestBuiltInHandlers(t *testing.T) {
	// Create a mock database
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock database: %v", err)
	}
	defer db.Close()

	// Create server
	authService := auth.NewService(db, "")
	server := NewServer(db, authService, 5.0, 10, nil)
	ctx := context.Background()

	// Test ping handler
	pingHandler := &PingHandler{}
	response, err := pingHandler.Handle(ctx, server, "test_user", nil)
	if err != nil {
		t.Errorf("Ping handler failed: %v", err)
	}
	respMap := response.(map[string]interface{})
	if respMap["message"] != "pong" {
		t.Error("Unexpected ping response")
	}

	// Test echo handler
	echoHandler := &EchoHandler{}
	testParams := json.RawMessage(`{"echo_test": "value"}`)
	response, err = echoHandler.Handle(ctx, server, "test_user", testParams)
	if err != nil {
		t.Errorf("Echo handler failed: %v", err)
	}
	respMap = response.(map[string]interface{})
	if respMap["sender"] != "test_user" {
		t.Error("Echo handler didn't include sender")
	}

	// Test server info handler
	infoHandler := &ServerInfoHandler{}
	response, err = infoHandler.Handle(ctx, server, "test_user", nil)
	if err != nil {
		t.Errorf("Server info handler failed: %v", err)
	}
	respMap = response.(map[string]interface{})
	if respMap["version"] != "1.0.0" {
		t.Error("Unexpected server version")
	}

	// Test user count handler
	countHandler := &UserCountHandler{}
	response, err = countHandler.Handle(ctx, server, "test_user", nil)
	if err != nil {
		t.Errorf("User count handler failed: %v", err)
	}
	respMap = response.(map[string]interface{})
	if _, ok := respMap["count"]; !ok {
		t.Error("User count handler didn't return count")
	}

	// Test list commands handler
	listHandler := &ListCommandsHandler{}
	response, err = listHandler.Handle(ctx, server, "test_user", nil)
	if err != nil {
		t.Errorf("List commands handler failed: %v", err)
	}
	respMap = response.(map[string]interface{})
	commands, ok := respMap["commands"].([]string)
	if !ok {
		t.Error("List commands handler didn't return commands array")
	}
	if len(commands) < 5 {
		t.Error("Expected at least 5 built-in commands")
	}
}

// MockServerHandler is a mock implementation of ServerMessageHandler for testing
type MockServerHandler struct {
	response interface{}
	err      error
	calls    int
}

func (h *MockServerHandler) Handle(ctx context.Context, server *Server, sender string, params json.RawMessage) (interface{}, error) {
	h.calls++
	return h.response, h.err
}
