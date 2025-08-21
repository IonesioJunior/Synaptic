package ws

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"strings"
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

// TestProcessServerMessage tests the processServerMessage function
func TestProcessServerMessage(t *testing.T) {
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

	// Register a test handler
	testHandler := &MockServerHandler{
		response: map[string]string{"result": "success"},
	}
	server.RegisterServerHandler("test_command", testHandler)

	// Create mock client
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := &Client{
		userID: "test_user",
		conn:   nil, // We're not testing the conn directly
		send:   make(chan []byte, 256),
		server: server,
		ctx:    ctx,
		cancel: cancel,
	}

	// Test 1: Missing signature
	t.Run("MissingSignature", func(t *testing.T) {
		msg := models.Message{
			Header: models.MessageHeader{
				From:        "test_user",
				To:          "server",
				MessageType: models.MessageTypeServer,
			},
			Body: models.MessageBody{
				Content: `{"command": "test_command", "request_id": "123"}`,
			},
		}

		server.processServerMessage(client, msg)

		// Check if error was sent to client
		select {
		case sentMsg := <-client.send:
			if !strings.Contains(string(sentMsg), "must be signed") {
				t.Errorf("Expected signature error, got: %s", sentMsg)
			}
		case <-time.After(100 * time.Millisecond):
			t.Error("Expected error message to be sent")
		}
	})

	// Test 2: Invalid command format
	t.Run("InvalidCommandFormat", func(t *testing.T) {
		msg := models.Message{
			Header: models.MessageHeader{
				From:        "test_user",
				To:          "server",
				MessageType: models.MessageTypeServer,
				Signature:   "dummy_signature",
			},
			Body: models.MessageBody{
				Content: `invalid json`,
			},
		}

		server.processServerMessage(client, msg)

		// Check if error was sent to client
		select {
		case sentMsg := <-client.send:
			if !strings.Contains(string(sentMsg), "Invalid server command format") {
				t.Errorf("Expected format error, got: %s", sentMsg)
			}
		case <-time.After(100 * time.Millisecond):
			t.Error("Expected error message to be sent")
		}
	})

	// Test 3: Valid message with valid signature
	t.Run("ValidMessage", func(t *testing.T) {
		serverCmd := models.ServerCommand{
			Command:   "test_command",
			RequestID: "test-456",
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

		// Sign the message
		signature := ed25519.Sign(privateKey, cmdJSON)
		msg.Header.Signature = base64.StdEncoding.EncodeToString(signature)

		// Mock database query for public key
		publicKeyStr := base64.StdEncoding.EncodeToString(publicKey)
		mock.ExpectQuery("SELECT public_key FROM users WHERE user_id = ?").
			WithArgs("test_user").
			WillReturnRows(sqlmock.NewRows([]string{"public_key"}).AddRow(publicKeyStr))

		// Process the message
		server.processServerMessage(client, msg)

		// Check if response was sent to client
		select {
		case sentMsg := <-client.send:
			var response models.Message
			if err := json.Unmarshal(sentMsg, &response); err != nil {
				t.Fatalf("Failed to unmarshal response: %v", err)
			}
			if response.Header.MessageType != models.MessageTypeDirect {
				t.Errorf("Expected direct message type, got: %s", response.Header.MessageType)
			}
			if !strings.Contains(response.Body.Content, "success") {
				t.Errorf("Expected success response, got: %s", response.Body.Content)
			}
		case <-time.After(100 * time.Millisecond):
			t.Error("Expected response message to be sent")
		}

		// Verify handler was called
		if testHandler.calls != 1 {
			t.Errorf("Handler called %d times, expected 1", testHandler.calls)
		}
	})

	// Test 4: Unknown command
	t.Run("UnknownCommand", func(t *testing.T) {
		serverCmd := models.ServerCommand{
			Command:   "unknown_command",
			RequestID: "test-789",
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

		// Sign the message
		signature := ed25519.Sign(privateKey, cmdJSON)
		msg.Header.Signature = base64.StdEncoding.EncodeToString(signature)

		// Mock database query for public key
		publicKeyStr := base64.StdEncoding.EncodeToString(publicKey)
		mock.ExpectQuery("SELECT public_key FROM users WHERE user_id = ?").
			WithArgs("test_user").
			WillReturnRows(sqlmock.NewRows([]string{"public_key"}).AddRow(publicKeyStr))

		// Process the message
		server.processServerMessage(client, msg)

		// Check if error was sent to client
		select {
		case sentMsg := <-client.send:
			if !strings.Contains(string(sentMsg), "Unknown command") {
				t.Errorf("Expected unknown command error, got: %s", sentMsg)
			}
		case <-time.After(100 * time.Millisecond):
			t.Error("Expected error message to be sent")
		}
	})
}

// TestSendServerResponse tests the sendServerResponse function
func TestSendServerResponse(t *testing.T) {
	// Create server
	server := &Server{
		clients: make(map[string]*Client),
	}

	// Create mock client
	client := &Client{
		userID: "test_user",
		conn:   nil, // We're not testing the conn directly
		send:   make(chan []byte, 256),
		server: server,
	}

	// Create original message
	originalMsg := models.Message{
		Header: models.MessageHeader{
			From:        "test_user",
			To:          "server",
			MessageType: models.MessageTypeServer,
		},
		Body: models.MessageBody{
			Content: `{"command": "test", "request_id": "req-123"}`,
		},
	}

	// Test response data
	responseData := map[string]string{
		"status": "success",
		"data":   "test data",
	}

	// Send response
	server.sendServerResponse(client, originalMsg, responseData, "req-123")

	// Check if response was sent
	select {
	case sentMsg := <-client.send:
		var response models.Message
		if err := json.Unmarshal(sentMsg, &response); err != nil {
			t.Fatalf("Failed to unmarshal response: %v", err)
		}

		// Verify response structure
		if response.Header.From != "server" {
			t.Errorf("Expected from 'server', got: %s", response.Header.From)
		}
		if response.Header.To != "test_user" {
			t.Errorf("Expected to 'test_user', got: %s", response.Header.To)
		}
		if response.Header.MessageType != models.MessageTypeDirect {
			t.Errorf("Expected message type '%s', got: %s", models.MessageTypeDirect, response.Header.MessageType)
		}

		// Parse response body
		var respBody models.ServerResponse
		if err := json.Unmarshal([]byte(response.Body.Content), &respBody); err != nil {
			t.Fatalf("Failed to unmarshal response body: %v", err)
		}

		if respBody.RequestID != "req-123" {
			t.Errorf("Expected request ID 'req-123', got: %s", respBody.RequestID)
		}
		if !respBody.Success {
			t.Error("Expected success to be true")
		}
		if respBody.Error != "" {
			t.Errorf("Expected no error, got: %s", respBody.Error)
		}

	case <-time.After(100 * time.Millisecond):
		t.Error("Response was not sent")
	}
}

// TestSendServerError tests the sendServerError function
func TestSendServerError(t *testing.T) {
	// Create server
	server := &Server{
		clients: make(map[string]*Client),
	}

	// Create mock client
	client := &Client{
		userID: "test_user",
		conn:   nil, // We're not testing the conn directly
		send:   make(chan []byte, 256),
		server: server,
	}

	// Create original message
	originalMsg := models.Message{
		Header: models.MessageHeader{
			From:        "test_user",
			To:          "server",
			MessageType: models.MessageTypeServer,
		},
		Body: models.MessageBody{
			Content: `{"command": "test", "request_id": "req-456"}`,
		},
	}

	// Send error
	server.sendServerError(client, originalMsg, "Test error message", "req-456")

	// Check if error was sent
	select {
	case sentMsg := <-client.send:
		var response models.Message
		if err := json.Unmarshal(sentMsg, &response); err != nil {
			t.Fatalf("Failed to unmarshal response: %v", err)
		}

		// Verify response structure
		if response.Header.From != "server" {
			t.Errorf("Expected from 'server', got: %s", response.Header.From)
		}
		if response.Header.To != "test_user" {
			t.Errorf("Expected to 'test_user', got: %s", response.Header.To)
		}
		if response.Header.MessageType != models.MessageTypeDirect {
			t.Errorf("Expected message type '%s', got: %s", models.MessageTypeDirect, response.Header.MessageType)
		}

		// Parse response body
		var respBody models.ServerResponse
		if err := json.Unmarshal([]byte(response.Body.Content), &respBody); err != nil {
			t.Fatalf("Failed to unmarshal response body: %v", err)
		}

		if respBody.RequestID != "req-456" {
			t.Errorf("Expected request ID 'req-456', got: %s", respBody.RequestID)
		}
		if respBody.Success {
			t.Error("Expected success to be false")
		}
		if respBody.Error != "Test error message" {
			t.Errorf("Expected error 'Test error message', got: %s", respBody.Error)
		}

	case <-time.After(100 * time.Millisecond):
		t.Error("Error response was not sent")
	}
}

// TestProcessServerMessageTimeout tests timeout handling in processServerMessage
func TestProcessServerMessageTimeout(t *testing.T) {
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

	// Register a slow handler that times out
	slowHandler := &MockServerHandler{
		response: map[string]string{"result": "should_timeout"},
		err:      context.DeadlineExceeded,
	}
	server.RegisterServerHandler("slow_command", slowHandler)

	// Create mock client
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := &Client{
		userID: "test_user",
		conn:   nil, // We're not testing the conn directly
		send:   make(chan []byte, 256),
		server: server,
		ctx:    ctx,
		cancel: cancel,
	}

	// Create message with slow command
	serverCmd := models.ServerCommand{
		Command:   "slow_command",
		RequestID: "timeout-test",
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

	// Sign the message
	signature := ed25519.Sign(privateKey, cmdJSON)
	msg.Header.Signature = base64.StdEncoding.EncodeToString(signature)

	// Mock database query for public key
	publicKeyStr := base64.StdEncoding.EncodeToString(publicKey)
	mock.ExpectQuery("SELECT public_key FROM users WHERE user_id = ?").
		WithArgs("test_user").
		WillReturnRows(sqlmock.NewRows([]string{"public_key"}).AddRow(publicKeyStr))

	// Process the message
	server.processServerMessage(client, msg)

	// Check if timeout error was sent to client
	select {
	case sentMsg := <-client.send:
		if !strings.Contains(string(sentMsg), "deadline exceeded") {
			t.Errorf("Expected timeout error, got: %s", sentMsg)
		}
	case <-time.After(200 * time.Millisecond):
		t.Error("Expected timeout error message to be sent")
	}
}
