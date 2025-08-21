package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/IonesioJunior/Synaptic/client-sdk/types"
)

// Mock WebSocket connection for testing
// TODO: Implement tests using this mock connection
// type mockConn struct {
// 	*websocket.Conn
// 	readMessages  [][]byte
// 	writeMessages [][]byte
// 	mu            sync.Mutex
// 	closed        bool
// 	readIndex     int
// }

// func (m *mockConn) WriteMessage(messageType int, data []byte) error {
// 	m.mu.Lock()
// 	defer m.mu.Unlock()
// 	if m.closed {
// 		return websocket.ErrCloseSent
// 	}
// 	m.writeMessages = append(m.writeMessages, data)
// 	return nil
// }

// func (m *mockConn) ReadMessage() (int, []byte, error) {
// 	m.mu.Lock()
// 	defer m.mu.Unlock()
// 	if m.closed {
// 		return 0, nil, websocket.ErrCloseSent
// 	}
// 	if m.readIndex >= len(m.readMessages) {
// 		return 0, nil, websocket.ErrCloseSent
// 	}
// 	msg := m.readMessages[m.readIndex]
// 	m.readIndex++
// 	return websocket.TextMessage, msg, nil
// }

// func (m *mockConn) Close() error {
// 	m.mu.Lock()
// 	defer m.mu.Unlock()
// 	m.closed = true
// 	return nil
// }

// func (m *mockConn) SetReadLimit(limit int64)                                            {}
// func (m *mockConn) SetReadDeadline(t time.Time) error                                   { return nil }
// func (m *mockConn) SetWriteDeadline(t time.Time) error                                  { return nil }
// func (m *mockConn) SetPongHandler(h func(string) error)                                 {}
// func (m *mockConn) WriteControl(messageType int, data []byte, deadline time.Time) error { return nil }

func TestClient_setState(t *testing.T) {
	config := &Config{
		ServerURL: "http://localhost",
		UserID:    "test",
		Username:  "Test",
		Debug:     true,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Test state transitions
	states := []types.ConnectionState{
		types.StateConnecting,
		types.StateConnected,
		types.StateReconnecting,
		types.StateDisconnected,
	}

	for _, state := range states {
		client.setState(state)
		if client.GetState() != state {
			t.Errorf("Expected state %v, got %v", state, client.GetState())
		}
	}
}

func TestClient_compareAndSwapState(t *testing.T) {
	config := &Config{
		ServerURL: "http://localhost",
		UserID:    "test",
		Username:  "Test",
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Set initial state
	client.setState(types.StateDisconnected)

	// Test successful swap
	if !client.compareAndSwapState(types.StateDisconnected, types.StateConnecting) {
		t.Error("Expected successful state swap")
	}

	if client.GetState() != types.StateConnecting {
		t.Errorf("Expected state %v, got %v", types.StateConnecting, client.GetState())
	}

	// Test failed swap (wrong current state)
	if client.compareAndSwapState(types.StateDisconnected, types.StateConnected) {
		t.Error("Expected failed state swap")
	}
}

func TestClient_logDebug(t *testing.T) {
	config := &Config{
		ServerURL: "http://localhost",
		UserID:    "test",
		Username:  "Test",
		Debug:     true,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Test with logger
	client.logDebug("Test message %s", "with args")

	// Test without logger
	client.logger = nil
	client.logDebug("Should not panic")
}

func TestClient_logError(t *testing.T) {
	config := &Config{
		ServerURL: "http://localhost",
		UserID:    "test",
		Username:  "Test",
		Debug:     true,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Test with logger
	client.logError("Error message %s", "with args")

	// Test without logger
	client.logger = nil
	client.logError("Should not panic")
}

func TestClient_handleDisconnect(t *testing.T) {
	// Create a test WebSocket server for a real connection
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		time.Sleep(100 * time.Millisecond)
	}))
	defer server.Close()

	// Connect to test server
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}

	config := &Config{
		ServerURL:     "http://localhost",
		UserID:        "test",
		Username:      "Test",
		AutoReconnect: false,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Set up disconnect callback with proper synchronization
	var disconnectCalled bool
	var mu sync.Mutex
	client.OnDisconnect(func(err error) {
		mu.Lock()
		disconnectCalled = true
		mu.Unlock()
	})

	// Set real connection
	client.setState(types.StateConnected)
	client.conn = conn

	// Handle disconnect
	client.handleDisconnect(nil)

	// Wait for callback
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	called := disconnectCalled
	mu.Unlock()

	if !called {
		t.Error("Disconnect callback not called")
	}

	if client.GetState() != types.StateDisconnected {
		t.Error("Client should be disconnected")
	}

	if client.conn != nil {
		t.Error("Connection should be nil")
	}
}

func TestClient_scheduleReconnect(t *testing.T) {
	config := &Config{
		ServerURL:        "http://localhost",
		UserID:           "test",
		Username:         "Test",
		AutoReconnect:    true,
		MaxReconnectWait: 5 * time.Second,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Set up reconnect callback with proper synchronization
	var reconnectCalled bool
	var mu sync.Mutex
	client.OnReconnect(func(attempt int) {
		mu.Lock()
		reconnectCalled = true
		mu.Unlock()
	})

	// Set initial state
	client.setState(types.StateDisconnected)

	// Schedule reconnect
	client.scheduleReconnect()

	// Wait for callback
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	called := reconnectCalled
	mu.Unlock()

	if !called {
		t.Error("Reconnect callback not called")
	}

	if client.GetState() != types.StateReconnecting {
		t.Error("Client should be in reconnecting state")
	}

	// Cancel to clean up
	if client.reconnectTimer != nil {
		client.reconnectTimer.Stop()
	}
}

func TestClient_processMessage(t *testing.T) {
	config := &Config{
		ServerURL: "http://localhost",
		UserID:    "test",
		Username:  "Test",
		Workers:   2,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Add message handler
	handledMsg := make(chan *types.Message, 1)
	client.AddMessageHandlerFunc(func(msg *types.Message) error {
		handledMsg <- msg
		return nil
	})

	// Process message
	msg := &types.Message{
		Header: types.MessageHeader{
			From: "sender",
			To:   "test",
		},
		Body: types.MessageBody{
			Content: "test message",
		},
	}

	client.processMessage(msg)

	// Wait for handler
	select {
	case received := <-handledMsg:
		if received.Body.Content != msg.Body.Content {
			t.Error("Message content mismatch")
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("Message not handled")
	}
}

func TestClient_readPump(t *testing.T) {
	// Create test WebSocket server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		}

		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		// Send test messages
		msg1 := types.Message{
			Header: types.MessageHeader{
				From: "server",
				To:   "client",
			},
			Body: types.MessageBody{
				Content: "message 1",
			},
		}

		data1, _ := json.Marshal(msg1)
		conn.WriteMessage(websocket.TextMessage, data1)

		// Keep connection open
		time.Sleep(100 * time.Millisecond)

		// Send encrypted message
		msg2 := types.Message{
			Header: types.MessageHeader{
				From:            "server",
				To:              "client",
				EncryptedKey:    "fake-key",
				EncryptionNonce: "fake-nonce",
			},
			Body: types.MessageBody{
				Content: "encrypted",
			},
		}

		data2, _ := json.Marshal(msg2)
		conn.WriteMessage(websocket.TextMessage, data2)

		time.Sleep(100 * time.Millisecond)
	}))
	defer server.Close()

	// Connect to server
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	config := &Config{
		ServerURL: server.URL,
		UserID:    "client",
		Username:  "Client",
		Debug:     true,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	client.conn = conn
	client.wg.Add(1)

	// Start read pump
	go client.readPump()

	// Wait for messages
	select {
	case msg := <-client.receiveChan:
		if msg.Body.Content != "message 1" {
			t.Errorf("Expected 'message 1', got '%s'", msg.Body.Content)
		}
	case <-time.After(200 * time.Millisecond):
		t.Error("No message received")
	}

	// Second message will fail decryption but should still be processed
	select {
	case <-client.errorChan:
		// Expected - decryption will fail
	case <-time.After(200 * time.Millisecond):
		// Also acceptable
	}

	// Clean up
	client.cancel()
	client.wg.Wait()
}

func TestClient_writePump(t *testing.T) {
	// Create test WebSocket server
	receivedMessages := make(chan []byte, 10)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		}

		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		// Read messages
		for {
			_, data, err := conn.ReadMessage()
			if err != nil {
				break
			}
			receivedMessages <- data
		}
	}))
	defer server.Close()

	// Connect to server
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	config := &Config{
		ServerURL: server.URL,
		UserID:    "client",
		Username:  "Client",
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	client.conn = conn
	client.wg.Add(1)

	// Start write pump
	go client.writePump()

	// Send test message
	msg := &types.Message{
		Header: types.MessageHeader{
			From: "client",
			To:   "server",
		},
		Body: types.MessageBody{
			Content: "test message",
		},
	}

	client.sendChan <- msg

	// Wait for message to be sent
	select {
	case data := <-receivedMessages:
		var received types.Message
		if err := json.Unmarshal(data, &received); err != nil {
			t.Fatalf("Failed to unmarshal: %v", err)
		}
		if received.Body.Content != "test message" {
			t.Errorf("Expected 'test message', got '%s'", received.Body.Content)
		}
	case <-time.After(200 * time.Millisecond):
		t.Error("Message not received by server")
	}

	// Clean up
	client.cancel()
	client.wg.Wait()
}

func TestClient_handleDisconnectWithAutoReconnect(t *testing.T) {
	// Create a test WebSocket server for a real connection
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Fatalf("Failed to upgrade connection: %v", err)
		}
		defer conn.Close()
		// Keep connection open for testing
		time.Sleep(1 * time.Second)
	}))
	defer server.Close()

	wsURL := strings.Replace(server.URL, "http://", "ws://", 1)

	config := &Config{
		ServerURL:        server.URL,
		UserID:           "test",
		Username:         "Test",
		AutoReconnect:    true,
		MaxReconnectWait: 5 * time.Second,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Set up callbacks with proper synchronization
	var disconnectCalled, reconnectCalled bool
	var mu sync.Mutex

	client.OnDisconnect(func(err error) {
		mu.Lock()
		disconnectCalled = true
		mu.Unlock()
	})

	client.OnReconnect(func(attempt int) {
		mu.Lock()
		reconnectCalled = true
		mu.Unlock()
	})

	// Establish a real connection
	dialer := websocket.DefaultDialer
	conn, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("Failed to dial WebSocket: %v", err)
	}

	// Simulate connection
	client.setState(types.StateConnected)
	client.conn = conn

	// Handle disconnect with auto-reconnect
	client.handleDisconnect(nil)

	// Wait for callbacks
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	dcCalled := disconnectCalled
	rcCalled := reconnectCalled
	mu.Unlock()

	if !dcCalled {
		t.Error("Disconnect callback not called")
	}

	if !rcCalled {
		t.Error("Reconnect callback not called")
	}

	// Clean up
	if client.reconnectTimer != nil {
		client.reconnectTimer.Stop()
	}
	client.cancel()
}

func TestClient_processMessageWithWorkerPoolExhausted(t *testing.T) {
	config := &Config{
		ServerURL: "http://localhost",
		UserID:    "test",
		Username:  "Test",
		Workers:   1, // Small worker pool
		Debug:     true,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Exhaust worker pool
	<-client.workerPool

	// Add handler
	handled := make(chan bool, 1)
	client.AddMessageHandlerFunc(func(msg *types.Message) error {
		handled <- true
		return nil
	})

	// Process message synchronously when pool exhausted
	msg := &types.Message{
		Header: types.MessageHeader{
			From: "sender",
			To:   "test",
		},
		Body: types.MessageBody{
			Content: "test",
		},
	}

	client.processMessage(msg)

	// Should still be handled
	select {
	case <-handled:
		// Success
	case <-time.After(100 * time.Millisecond):
		t.Error("Message not handled when worker pool exhausted")
	}

	// Return worker to pool
	client.workerPool <- struct{}{}
}

func BenchmarkClient_setState(b *testing.B) {
	config := &Config{
		ServerURL: "http://localhost",
		UserID:    "bench",
		Username:  "Bench",
	}

	client, _ := NewClient(config)

	states := []types.ConnectionState{
		types.StateDisconnected,
		types.StateConnecting,
		types.StateConnected,
		types.StateReconnecting,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		client.setState(states[i%len(states)])
	}
}

func BenchmarkClient_processMessage(b *testing.B) {
	config := &Config{
		ServerURL: "http://localhost",
		UserID:    "bench",
		Username:  "Bench",
		Workers:   10,
	}

	client, _ := NewClient(config)

	// Add simple handler
	client.AddMessageHandlerFunc(func(msg *types.Message) error {
		return nil
	})

	msg := &types.Message{
		Header: types.MessageHeader{
			From: "sender",
			To:   "bench",
		},
		Body: types.MessageBody{
			Content: "benchmark message",
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		client.processMessage(msg)
	}
}
