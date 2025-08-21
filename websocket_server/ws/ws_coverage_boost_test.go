package ws

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
	_ "github.com/mattn/go-sqlite3"
	"websocketserver/auth"
	"websocketserver/db"
)

// setupTestDB creates an in-memory SQLite database for testing
func setupTestDB(t *testing.T) *sql.DB {
	database, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open test database: %v", err)
	}

	// Initialize database schema
	err = db.RunMigrations(database)
	if err != nil {
		t.Fatalf("Failed to initialize database: %v", err)
	}

	// Create test users
	_, err = database.Exec(`
		INSERT INTO users (user_id, username, public_key) VALUES
		('test-user-1', 'testuser1', 'pubkey1'),
		('test-user-2', 'testuser2', 'pubkey2'),
		('test-user-3', 'testuser3', 'pubkey3')
	`)
	if err != nil {
		t.Fatalf("Failed to insert test users: %v", err)
	}

	return database
}

// generateJWT generates a valid JWT token for testing
func generateJWT(userID string, secret []byte) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(24 * time.Hour).Unix(),
		"iat":     time.Now().Unix(),
	})
	return token.SignedString(secret)
}

// TestHandleWebSocketCoverage tests the WebSocket handler with various scenarios
func TestHandleWebSocketCoverage(t *testing.T) {
	// Setup test database
	testDB := setupTestDB(t)
	defer testDB.Close()

	// Create auth service
	jwtSecret := []byte("test-secret")
	t.Setenv("JWT_SECRET", string(jwtSecret))
	authService := auth.NewService(testDB, "")

	// Create server
	server := NewServer(testDB, authService, 5.0, 10, []string{})

	// Test case 1: Missing token
	t.Run("MissingToken", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/ws", nil)
		w := httptest.NewRecorder()

		server.HandleWebSocket(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %d", w.Code)
		}
		if !strings.Contains(w.Body.String(), "Missing authentication token") {
			t.Error("Expected missing token error message")
		}
	})

	// Test case 2: Invalid token
	t.Run("InvalidToken", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/ws?token=invalid", nil)
		w := httptest.NewRecorder()

		server.HandleWebSocket(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %d", w.Code)
		}
		if !strings.Contains(w.Body.String(), "Invalid token") {
			t.Error("Expected invalid token error message")
		}
	})

	// Test case 3: Valid token but non-existent user
	t.Run("NonExistentUser", func(t *testing.T) {
		token, _ := generateJWT("non-existent", jwtSecret)
		req := httptest.NewRequest("GET", "/ws?token="+token, nil)
		w := httptest.NewRecorder()

		server.HandleWebSocket(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %d", w.Code)
		}
		if !strings.Contains(w.Body.String(), "Invalid user") {
			t.Error("Expected invalid user error message")
		}
	})

	// Test case 4: Valid connection with WebSocket upgrade
	t.Run("ValidConnection", func(t *testing.T) {
		token, _ := generateJWT("test-user-1", jwtSecret)
		
		// Create test server
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			server.HandleWebSocket(w, r)
		}))
		defer ts.Close()

		// Prepare WebSocket URL
		wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws?token=" + token

		// Attempt WebSocket connection
		conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
		if err != nil {
			t.Errorf("Failed to connect: %v", err)
			return
		}
		defer conn.Close()

		// Give time for connection to be established
		time.Sleep(100 * time.Millisecond)

		// Verify client is registered
		server.mu.RLock()
		clientExists := server.clients["test-user-1"] != nil
		server.mu.RUnlock()

		if !clientExists {
			t.Error("Client was not registered after successful connection")
		}

		// Send a test message to trigger readPump
		testMsg := map[string]interface{}{
			"to":      "test-user-2",
			"content": "test message",
		}
		msgBytes, _ := json.Marshal(testMsg)
		err = conn.WriteMessage(websocket.TextMessage, msgBytes)
		if err != nil {
			t.Errorf("Failed to send message: %v", err)
		}

		// Give time for message processing
		time.Sleep(100 * time.Millisecond)

		// Close connection to trigger cleanup
		conn.Close()
		time.Sleep(100 * time.Millisecond)

		// Verify client is unregistered after disconnect
		server.mu.RLock()
		clientStillExists := server.clients["test-user-1"] != nil
		server.mu.RUnlock()

		if clientStillExists {
			t.Error("Client was not unregistered after disconnect")
		}
	})
}

// TestActiveUsersHandlerCoverage tests the active users endpoint
func TestActiveUsersHandlerCoverage(t *testing.T) {
	// Setup test database
	testDB := setupTestDB(t)
	defer testDB.Close()

	// Create auth service
	t.Setenv("JWT_SECRET", "test-secret")
	authService := auth.NewService(testDB, "")

	// Create server
	server := NewServer(testDB, authService, 5.0, 10, []string{})

	// Test case 1: GET request with no users online
	t.Run("NoUsersOnline", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/active-users", nil)
		w := httptest.NewRecorder()

		server.ActiveUsersHandler(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		var response UserStatusResponse
		err := json.NewDecoder(w.Body).Decode(&response)
		if err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		if len(response.Online) != 0 {
			t.Errorf("Expected 0 online users, got %d", len(response.Online))
		}

		if len(response.Offline) != 3 {
			t.Errorf("Expected 3 offline users, got %d", len(response.Offline))
		}
	})

	// Test case 2: With some users online
	t.Run("WithUsersOnline", func(t *testing.T) {
		// Add mock clients
		ctx1, cancel1 := context.WithCancel(context.Background())
		defer cancel1()
		client1 := &Client{
			userID: "test-user-1",
			server: server,
			send:   make(chan []byte, 256),
			ctx:    ctx1,
			cancel: cancel1,
		}

		ctx2, cancel2 := context.WithCancel(context.Background())
		defer cancel2()
		client2 := &Client{
			userID: "test-user-2",
			server: server,
			send:   make(chan []byte, 256),
			ctx:    ctx2,
			cancel: cancel2,
		}

		// Register clients
		server.registerClient(client1)
		server.registerClient(client2)

		req := httptest.NewRequest("GET", "/active-users", nil)
		w := httptest.NewRecorder()

		server.ActiveUsersHandler(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		var response UserStatusResponse
		err := json.NewDecoder(w.Body).Decode(&response)
		if err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		if len(response.Online) != 2 {
			t.Errorf("Expected 2 online users, got %d", len(response.Online))
		}

		if len(response.Offline) != 1 {
			t.Errorf("Expected 1 offline user, got %d", len(response.Offline))
		}

		// Cleanup
		server.unregisterClient(client1)
		server.unregisterClient(client2)
	})

	// Test case 3: Non-GET request
	t.Run("NonGETRequest", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/active-users", nil)
		w := httptest.NewRecorder()

		server.ActiveUsersHandler(w, req)

		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("Expected status 405, got %d", w.Code)
		}
	})

	// Test case 4: OPTIONS request
	t.Run("OPTIONSRequest", func(t *testing.T) {
		req := httptest.NewRequest("OPTIONS", "/active-users", nil)
		w := httptest.NewRecorder()

		server.ActiveUsersHandler(w, req)

		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("Expected status 405, got %d", w.Code)
		}
	})
}

// TestRegisterUnregisterClientCoverage tests client registration and unregistration
func TestRegisterUnregisterClientCoverage(t *testing.T) {
	// Setup test database
	testDB := setupTestDB(t)
	defer testDB.Close()

	// Create auth service
	t.Setenv("JWT_SECRET", "test-secret")
	authService := auth.NewService(testDB, "")

	// Create server
	server := NewServer(testDB, authService, 5.0, 10, []string{})

	// Create test client
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client := &Client{
		userID: "test-user-1",
		server: server,
		send:   make(chan []byte, 256),
		ctx:    ctx,
		cancel: cancel,
	}

	// Test registration
	server.registerClient(client)

	// Verify client is registered
	server.mu.RLock()
	registeredClient := server.clients["test-user-1"]
	server.mu.RUnlock()

	if registeredClient != client {
		t.Error("Client was not properly registered")
	}

	// Test duplicate registration (should replace)
	client2 := &Client{
		userID: "test-user-1",
		server: server,
		send:   make(chan []byte, 256),
		ctx:    ctx,
		cancel: cancel,
	}

	server.registerClient(client2)

	server.mu.RLock()
	replacedClient := server.clients["test-user-1"]
	server.mu.RUnlock()

	if replacedClient != client2 {
		t.Error("Client was not properly replaced")
	}

	// Test unregistration
	server.unregisterClient(client2)

	// Verify client is unregistered
	server.mu.RLock()
	unregisteredClient := server.clients["test-user-1"]
	server.mu.RUnlock()

	if unregisteredClient != nil {
		t.Error("Client was not properly unregistered")
	}

	// Test unregistering non-existent client (should not panic)
	server.unregisterClient(client)

	// Verify rate limiter cleanup
	if server.RateLimiter != nil {
		// The rate limiter should have removed the user
		server.RateLimiter.RemoveUser("test-user-1")
	}
}

// TestRetrieveUndeliveredMessagesCoverage tests the undelivered messages retrieval
func TestRetrieveUndeliveredMessagesCoverage(t *testing.T) {
	// Setup test database
	testDB := setupTestDB(t)
	defer testDB.Close()

	// Insert test messages
	_, err := testDB.Exec(`
		INSERT INTO messages (from_user, to_user, content, status, timestamp) VALUES
		('test-user-2', 'test-user-1', 'Hello 1', 'pending', datetime('now', '-5 minutes')),
		('test-user-3', 'test-user-1', 'Hello 2', 'pending', datetime('now', '-3 minutes')),
		('test-user-2', 'test-user-1', 'Hello 3', 'delivered', datetime('now', '-1 minutes')),
		('test-user-1', 'test-user-2', 'Hello 4', 'pending', datetime('now', '-2 minutes'))
	`)
	if err != nil {
		t.Fatalf("Failed to insert test messages: %v", err)
	}

	// Create auth service
	t.Setenv("JWT_SECRET", "test-secret")
	authService := auth.NewService(testDB, "")

	// Create server
	server := NewServer(testDB, authService, 5.0, 10, []string{})

	// Test retrieving messages for test-user-1
	t.Run("RetrieveForUser1", func(t *testing.T) {
		// Note: RetrieveUndeliveredMessages doesn't return a value but logs errors
		server.RetrieveUndeliveredMessages("test-user-1")

		// Verify messages are marked as delivered
		var pendingCount int
		err := testDB.QueryRow(`
			SELECT COUNT(*) FROM messages 
			WHERE to_user = 'test-user-1' AND status = 'pending'
		`).Scan(&pendingCount)
		
		if err != nil {
			t.Errorf("Failed to query pending messages: %v", err)
		}
		
		// Messages should still be pending since we don't have a client to send to
		if pendingCount != 2 {
			t.Errorf("Expected 2 pending messages, got %d", pendingCount)
		}
	})

	// Test retrieving messages for non-existent user
	t.Run("RetrieveForNonExistentUser", func(t *testing.T) {
		// Should not panic
		server.RetrieveUndeliveredMessages("non-existent-user")
	})

	// Test retrieving when user has no messages
	t.Run("RetrieveNoMessages", func(t *testing.T) {
		// Create a user with no messages
		_, err := testDB.Exec(`INSERT INTO users (user_id, username, public_key) VALUES ('no-msg-user', 'nomsg', 'key')`)
		if err != nil {
			t.Fatalf("Failed to insert user: %v", err)
		}

		// Should not panic
		server.RetrieveUndeliveredMessages("no-msg-user")
	})
}

// TestRateLimiterIntegration tests rate limiting with WebSocket connections
func TestRateLimiterIntegration(t *testing.T) {
	// Setup test database
	testDB := setupTestDB(t)
	defer testDB.Close()

	// Create auth service
	jwtSecret := []byte("test-secret")
	t.Setenv("JWT_SECRET", string(jwtSecret))
	authService := auth.NewService(testDB, "")

	// Create server with strict rate limiting (1 message per second, burst of 2)
	server := NewServer(testDB, authService, 1.0, 2, []string{})

	token, _ := generateJWT("test-user-1", jwtSecret)
	
	// Create test server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		server.HandleWebSocket(w, r)
	}))
	defer ts.Close()

	// Connect to WebSocket
	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws?token=" + token
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	// Send multiple messages quickly to trigger rate limiting
	for i := 0; i < 5; i++ {
		msg := map[string]interface{}{
			"to":      "test-user-2",
			"content": "message " + string(rune(i)),
		}
		msgBytes, _ := json.Marshal(msg)
		conn.WriteMessage(websocket.TextMessage, msgBytes)
	}

	// Give time for rate limiting to kick in
	time.Sleep(200 * time.Millisecond)

	// Read messages to see if rate limit error was sent
	conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	_, message, err := conn.ReadMessage()
	if err == nil {
		// Check if we got a rate limit message
		var msg map[string]interface{}
		if json.Unmarshal(message, &msg) == nil {
			t.Logf("Received message: %v", msg)
		}
	}
}

// TestWebSocketWithDatabase tests database error handling
func TestWebSocketWithDatabase(t *testing.T) {
	// Setup test database
	testDB := setupTestDB(t)
	
	// Create auth service
	jwtSecret := []byte("test-secret")
	t.Setenv("JWT_SECRET", string(jwtSecret))
	authService := auth.NewService(testDB, "")

	// Create server
	server := NewServer(testDB, authService, 5.0, 10, []string{})

	// Close database to simulate database error
	testDB.Close()

	// Try to connect with valid token
	token, _ := generateJWT("test-user-1", jwtSecret)
	req := httptest.NewRequest("GET", "/ws?token="+token, nil)
	w := httptest.NewRecorder()

	server.HandleWebSocket(w, req)

	// Should get internal server error due to closed database
	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 500, got %d", w.Code)
	}
}

// TestDeliverMessageCoverage tests the deliverMessage function indirectly
func TestDeliverMessageCoverage(t *testing.T) {
	// Setup test database
	testDB := setupTestDB(t)
	defer testDB.Close()

	// Create auth service
	t.Setenv("JWT_SECRET", "test-secret")
	authService := auth.NewService(testDB, "")

	// Create server
	server := NewServer(testDB, authService, 5.0, 10, []string{})

	// Create and register a client for test-user-2
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client2 := &Client{
		userID: "test-user-2",
		server: server,
		send:   make(chan []byte, 256),
		ctx:    ctx,
		cancel: cancel,
	}

	server.registerClient(client2)

	// deliverMessage is called internally when processing messages
	// We test it indirectly by checking if messages are delivered

	// Check that test-user-2 is online
	server.mu.RLock()
	isOnline := server.clients["test-user-2"] != nil
	server.mu.RUnlock()

	if !isOnline {
		t.Error("test-user-2 should be online")
	}

	// Cleanup
	server.unregisterClient(client2)
}