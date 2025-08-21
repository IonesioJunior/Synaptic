package client

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"

	"github.com/genericwsserver/client-sdk/auth"
	"github.com/genericwsserver/client-sdk/types"
)

// Mock WebSocket server for testing
type mockWSServer struct {
	server     *httptest.Server
	upgrader   websocket.Upgrader
	conns      []*websocket.Conn
	connsMu    sync.Mutex
	messages   [][]byte
	messagesMu sync.Mutex
}

func newMockWSServer() *mockWSServer {
	m := &mockWSServer{
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		},
	}
	
	mux := http.NewServeMux()
	
	// WebSocket endpoint
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		if token == "" {
			http.Error(w, "Missing token", http.StatusUnauthorized)
			return
		}
		
		conn, err := m.upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		
		m.connsMu.Lock()
		m.conns = append(m.conns, conn)
		m.connsMu.Unlock()
		
		// Read messages
		go func() {
			defer conn.Close()
			for {
				_, message, err := conn.ReadMessage()
				if err != nil {
					break
				}
				
				m.messagesMu.Lock()
				m.messages = append(m.messages, message)
				m.messagesMu.Unlock()
				
				// Echo back for testing
				conn.WriteMessage(websocket.TextMessage, message)
			}
		}()
	})
	
	// Auth endpoints
	mux.HandleFunc("/auth/check-userid/", func(w http.ResponseWriter, r *http.Request) {
		userID := strings.TrimPrefix(r.URL.Path, "/auth/check-userid/")
		exists := userID == "existing-user"
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(types.UserExistsResponse{Exists: exists})
	})
	
	mux.HandleFunc("/auth/register", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"message": "registered"})
	})
	
	mux.HandleFunc("/auth/login", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("verify") == "true" {
			// Return token
			token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
				"user_id": "test-user",
				"exp":     time.Now().Add(24 * time.Hour).Unix(),
			})
			tokenString, _ := token.SignedString([]byte("test-secret"))
			
			json.NewEncoder(w).Encode(types.TokenResponse{Token: tokenString})
		} else {
			// Return challenge
			json.NewEncoder(w).Encode(types.ChallengeResponse{
				Challenge: base64.StdEncoding.EncodeToString([]byte("test-challenge")),
			})
		}
	})
	
	mux.HandleFunc("/auth/users/", func(w http.ResponseWriter, r *http.Request) {
		userID := strings.TrimPrefix(r.URL.Path, "/auth/users/")
		
		if userID == "nonexistent" {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}
		
		user := types.User{
			UserID:          userID,
			Username:        "Test User",
			PublicKey:       base64.StdEncoding.EncodeToString(make([]byte, 32)),
			X25519PublicKey: base64.StdEncoding.EncodeToString(make([]byte, 32)),
			CreatedAt:       time.Now(),
		}
		
		json.NewEncoder(w).Encode(user)
	})
	
	m.server = httptest.NewServer(mux)
	return m
}

func (m *mockWSServer) Close() {
	m.connsMu.Lock()
	for _, conn := range m.conns {
		conn.Close()
	}
	m.connsMu.Unlock()
	m.server.Close()
}

func (m *mockWSServer) GetMessages() [][]byte {
	m.messagesMu.Lock()
	defer m.messagesMu.Unlock()
	return append([][]byte{}, m.messages...)
}

func (m *mockWSServer) SendToClients(data []byte) {
	m.connsMu.Lock()
	defer m.connsMu.Unlock()
	
	for _, conn := range m.conns {
		conn.WriteMessage(websocket.TextMessage, data)
	}
}

func TestClient_Connect(t *testing.T) {
	server := newMockWSServer()
	defer server.Close()
	
	config := &Config{
		ServerURL:  server.server.URL,
		UserID:     "test-user",
		Username:   "Test User",
		PrivateKey: "",
		AutoReconnect: false,
		InsecureTLS: true,
	}
	
	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Disconnect()
	
	// Test successful connection
	err = client.Connect()
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	
	if !client.IsConnected() {
		t.Error("Client should be connected")
	}
	
	// Test connection when already connected
	err = client.Connect()
	if err == nil {
		t.Error("Should error when already connected")
	}
}

func TestClient_ConnectWithExistingUser(t *testing.T) {
	server := newMockWSServer()
	defer server.Close()
	
	config := &Config{
		ServerURL:  server.server.URL,
		UserID:     "existing-user",
		Username:   "Existing User",
		AutoReconnect: false,
		InsecureTLS: true,
	}
	
	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Disconnect()
	
	err = client.Connect()
	if err != nil {
		t.Fatalf("Failed to connect with existing user: %v", err)
	}
	
	if !client.IsConnected() {
		t.Error("Client should be connected")
	}
}

func TestClient_SendMessage(t *testing.T) {
	server := newMockWSServer()
	defer server.Close()
	
	config := &Config{
		ServerURL:  server.server.URL,
		UserID:     "sender",
		Username:   "Sender",
		AutoReconnect: false,
		InsecureTLS: true,
	}
	
	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Disconnect()
	
	err = client.Connect()
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	
	// Send a message
	err = client.SendMessage("recipient", "Hello, World!", false)
	if err != nil {
		t.Fatalf("Failed to send message: %v", err)
	}
	
	// Wait for message to be processed
	time.Sleep(100 * time.Millisecond)
	
	// Check that message was sent
	messages := server.GetMessages()
	if len(messages) == 0 {
		t.Fatal("No messages received by server")
	}
	
	var msg types.Message
	if err := json.Unmarshal(messages[0], &msg); err != nil {
		t.Fatalf("Failed to unmarshal message: %v", err)
	}
	
	if msg.Header.From != "sender" {
		t.Errorf("Expected from 'sender', got '%s'", msg.Header.From)
	}
	
	if msg.Header.To != "recipient" {
		t.Errorf("Expected to 'recipient', got '%s'", msg.Header.To)
	}
	
	if msg.Body.Content != "Hello, World!" {
		t.Errorf("Expected content 'Hello, World!', got '%s'", msg.Body.Content)
	}
}

func TestClient_SendMessageWithSignature(t *testing.T) {
	server := newMockWSServer()
	defer server.Close()
	
	// Generate keys for testing
	privKey, err := auth.LoadPrivateKeyFromBase64("yO3XCiGaY+qJEnJHFWNf/L7O2qYz0xqJD1tUvNQsXsLPPQrN1p/BPVMok5b/VIzz8JdQHzy3JNNin5hJLkXl+Q==")
	if err != nil {
		privKey = nil // Use generated keys
	}
	
	config := &Config{
		ServerURL:  server.server.URL,
		UserID:     "signer",
		Username:   "Signer",
		PrivateKey: base64.StdEncoding.EncodeToString(privKey),
		AutoReconnect: false,
		InsecureTLS: true,
	}
	
	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Disconnect()
	
	err = client.Connect()
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	
	// Send signed message
	err = client.SendMessage("recipient", "Signed message", true)
	if err != nil {
		t.Fatalf("Failed to send signed message: %v", err)
	}
	
	// Wait for message
	time.Sleep(100 * time.Millisecond)
	
	messages := server.GetMessages()
	if len(messages) == 0 {
		t.Fatal("No messages received")
	}
	
	var msg types.Message
	json.Unmarshal(messages[0], &msg)
	
	if msg.Header.Signature == "" {
		t.Error("Message should have signature")
	}
}

func TestClient_Broadcast(t *testing.T) {
	server := newMockWSServer()
	defer server.Close()
	
	config := &Config{
		ServerURL:  server.server.URL,
		UserID:     "broadcaster",
		Username:   "Broadcaster",
		AutoReconnect: false,
		InsecureTLS: true,
	}
	
	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Disconnect()
	
	err = client.Connect()
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	
	// Send broadcast
	err = client.Broadcast("Hello everyone!")
	if err != nil {
		t.Fatalf("Failed to broadcast: %v", err)
	}
	
	// Wait for message
	time.Sleep(100 * time.Millisecond)
	
	messages := server.GetMessages()
	if len(messages) == 0 {
		t.Fatal("No messages received")
	}
	
	var msg types.Message
	json.Unmarshal(messages[0], &msg)
	
	if msg.Header.To != "broadcast" {
		t.Errorf("Expected to 'broadcast', got '%s'", msg.Header.To)
	}
	
	if !msg.Header.IsBroadcast {
		t.Error("IsBroadcast should be true")
	}
	
	if msg.Header.Signature != "" {
		t.Error("Broadcast should not have signature")
	}
}

func TestClient_MessageHandlers(t *testing.T) {
	server := newMockWSServer()
	defer server.Close()
	
	config := &Config{
		ServerURL:  server.server.URL,
		UserID:     "handler-test",
		Username:   "Handler Test",
		AutoReconnect: false,
		InsecureTLS: true,
		Workers: 2,
	}
	
	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Disconnect()
	
	// Add message handler
	received := make(chan *types.Message, 1)
	client.AddMessageHandlerFunc(func(msg *types.Message) error {
		received <- msg
		return nil
	})
	
	err = client.Connect()
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	
	// Server sends a message to client
	testMsg := types.Message{
		Header: types.MessageHeader{
			From:      "server",
			To:        "handler-test",
			Timestamp: time.Now(),
		},
		Body: types.MessageBody{
			Content: "Test message",
		},
	}
	
	data, _ := json.Marshal(testMsg)
	server.SendToClients(data)
	
	// Wait for handler to receive message
	select {
	case msg := <-received:
		if msg.Header.From != "server" {
			t.Errorf("Expected from 'server', got '%s'", msg.Header.From)
		}
		if msg.Body.Content != "Test message" {
			t.Errorf("Expected content 'Test message', got '%s'", msg.Body.Content)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for message handler")
	}
}

func TestClient_GetUserInfo(t *testing.T) {
	server := newMockWSServer()
	defer server.Close()
	
	config := &Config{
		ServerURL:  server.server.URL,
		UserID:     "test-user",
		Username:   "Test User",
		AutoReconnect: false,
		InsecureTLS: true,
	}
	
	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Disconnect()
	
	// Get user info
	user, err := client.GetUserInfo("some-user")
	if err != nil {
		t.Fatalf("Failed to get user info: %v", err)
	}
	
	if user.UserID != "some-user" {
		t.Errorf("Expected UserID 'some-user', got '%s'", user.UserID)
	}
	
	// Test cache
	user2, err := client.GetUserInfo("some-user")
	if err != nil {
		t.Fatalf("Failed to get cached user info: %v", err)
	}
	
	if user2 != user {
		t.Error("Should return cached user object")
	}
	
	// Test nonexistent user
	_, err = client.GetUserInfo("nonexistent")
	if err == nil {
		t.Error("Expected error for nonexistent user")
	}
}

func TestClient_VerifyMessageSignature(t *testing.T) {
	server := newMockWSServer()
	defer server.Close()
	
	config := &Config{
		ServerURL:  server.server.URL,
		UserID:     "verifier",
		Username:   "Verifier",
		AutoReconnect: false,
		InsecureTLS: true,
	}
	
	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Disconnect()
	
	// Create a signed message
	msg := &types.Message{
		Header: types.MessageHeader{
			From:      "test-user",
			To:        "verifier",
			Signature: "dGVzdC1zaWduYXR1cmU=", // base64 "test-signature"
		},
		Body: types.MessageBody{
			Content: "Signed content",
		},
	}
	
	// This will fail because we're using mock data
	valid, err := client.VerifyMessageSignature(msg)
	if err != nil {
		t.Logf("Expected verification error with mock data: %v", err)
	}
	
	if valid {
		t.Error("Should not verify with mock signature")
	}
	
	// Test message without signature
	msg.Header.Signature = ""
	valid, err = client.VerifyMessageSignature(msg)
	if err != nil {
		t.Errorf("Should not error for missing signature: %v", err)
	}
	
	if valid {
		t.Error("Should return false for missing signature")
	}
}

func TestClient_ConnectionCallbacks(t *testing.T) {
	server := newMockWSServer()
	defer server.Close()
	
	config := &Config{
		ServerURL:  server.server.URL,
		UserID:     "callback-test",
		Username:   "Callback Test",
		AutoReconnect: false,
		InsecureTLS: true,
	}
	
	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	
	// Set up callbacks
	connected := make(chan bool, 1)
	disconnected := make(chan error, 1)
	
	client.OnConnect(func() {
		connected <- true
	})
	
	client.OnDisconnect(func(err error) {
		disconnected <- err
	})
	
	// Connect
	err = client.Connect()
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	
	// Wait for connect callback
	select {
	case <-connected:
		// Success
	case <-time.After(2 * time.Second):
		t.Fatal("Connect callback not called")
	}
	
	// Disconnect
	client.Disconnect()
	
	// Wait for disconnect callback
	select {
	case <-disconnected:
		// Success
	case <-time.After(2 * time.Second):
		t.Fatal("Disconnect callback not called")
	}
}

func TestClient_GetMetrics(t *testing.T) {
	server := newMockWSServer()
	defer server.Close()
	
	config := &Config{
		ServerURL:  server.server.URL,
		UserID:     "metrics-test",
		Username:   "Metrics Test",
		AutoReconnect: false,
		InsecureTLS: true,
	}
	
	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Disconnect()
	
	err = client.Connect()
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	
	// Send some messages
	client.SendMessage("user1", "msg1", false)
	client.SendMessage("user2", "msg2", false)
	client.Broadcast("broadcast")
	
	time.Sleep(100 * time.Millisecond)
	
	sent, received, reconnects, errors := client.GetMetrics()
	
	if sent != 3 {
		t.Errorf("Expected 3 messages sent, got %d", sent)
	}
	
	// Note: received will be 0 unless server echoes back
	t.Logf("Metrics - Sent: %d, Received: %d, Reconnects: %d, Errors: %d",
		sent, received, reconnects, errors)
}

func TestClient_ErrorChannel(t *testing.T) {
	server := newMockWSServer()
	defer server.Close()
	
	config := &Config{
		ServerURL:  server.server.URL,
		UserID:     "error-test",
		Username:   "Error Test",
		AutoReconnect: false,
		InsecureTLS: true,
	}
	
	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Disconnect()
	
	errorChan := client.GetErrorChannel()
	
	// Add handler that returns error
	client.AddMessageHandlerFunc(func(msg *types.Message) error {
		return errors.New("test error")
	})
	
	err = client.Connect()
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	
	// Send message to trigger handler error
	testMsg := types.Message{
		Header: types.MessageHeader{
			From: "server",
			To:   "error-test",
		},
		Body: types.MessageBody{
			Content: "trigger error",
		},
	}
	
	data, _ := json.Marshal(testMsg)
	server.SendToClients(data)
	
	// Wait for error
	select {
	case err := <-errorChan:
		if !strings.Contains(err.Error(), "handler error") {
			t.Errorf("Expected handler error, got: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for error")
	}
}

func TestClient_SendMessageTimeout(t *testing.T) {
	server := newMockWSServer()
	defer server.Close()
	
	config := &Config{
		ServerURL:         server.server.URL,
		UserID:            "timeout-test",
		Username:          "Timeout Test",
		AutoReconnect:     false,
		InsecureTLS:       true,
		MessageBufferSize: 1, // Very small buffer
	}
	
	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	
	// Don't connect, so sends will timeout
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	
	client.ctx = ctx
	
	err = client.SendMessage("recipient", "message", false)
	if err == nil {
		t.Error("Expected timeout error")
	}
}

func TestClient_InvalidConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name:    "missing server URL",
			config:  &Config{UserID: "test", Username: "Test"},
			wantErr: true,
		},
		{
			name:    "valid config",
			config:  &Config{ServerURL: "http://localhost", UserID: "test", Username: "Test"},
			wantErr: false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewClient(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewClient() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestClient_ConnectionState(t *testing.T) {
	server := newMockWSServer()
	defer server.Close()
	
	config := &Config{
		ServerURL:  server.server.URL,
		UserID:     "state-test",
		Username:   "State Test",
		AutoReconnect: false,
		InsecureTLS: true,
	}
	
	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Disconnect()
	
	// Initial state
	if client.GetState() != types.StateDisconnected {
		t.Errorf("Initial state should be Disconnected, got %s", client.GetState())
	}
	
	if client.IsConnected() {
		t.Error("Should not be connected initially")
	}
	
	// Connect
	err = client.Connect()
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	
	if client.GetState() != types.StateConnected {
		t.Errorf("State should be Connected, got %s", client.GetState())
	}
	
	if !client.IsConnected() {
		t.Error("Should be connected")
	}
	
	// Disconnect
	client.Disconnect()
	
	if client.GetState() != types.StateDisconnected {
		t.Errorf("State should be Disconnected after disconnect, got %s", client.GetState())
	}
}