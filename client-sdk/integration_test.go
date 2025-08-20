//go:build integration
// +build integration

package client

import (
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/genericwsserver/client-sdk/types"
	"github.com/gorilla/websocket"
)

// These tests require a running WebSocket server
// Run with: go test -tags=integration -v

func getTestServerURL() string {
	url := os.Getenv("TEST_WS_SERVER_URL")
	if url == "" {
		url = "https://localhost:8443"
	}
	return url
}

func TestIntegrationConnect(t *testing.T) {
	config := &Config{
		ServerURL:     getTestServerURL(),
		UserID:        fmt.Sprintf("test-user-%d", time.Now().Unix()),
		Username:      "Test User",
		AutoReconnect: false,
		Debug:         true,
		InsecureTLS:   true,
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

	if !client.IsConnected() {
		t.Error("Client should be connected")
	}

	// Wait for connection to stabilize
	time.Sleep(100 * time.Millisecond)

	// Test disconnection
	err = client.Disconnect()
	if err != nil {
		t.Errorf("Failed to disconnect: %v", err)
	}

	if client.IsConnected() {
		t.Error("Client should be disconnected")
	}
}

func TestIntegrationMessageExchange(t *testing.T) {
	// Create two clients
	config1 := &Config{
		ServerURL:   getTestServerURL(),
		UserID:      fmt.Sprintf("test-user1-%d", time.Now().Unix()),
		Username:    "Test User 1",
		Debug:       true,
		InsecureTLS: true,
	}

	config2 := &Config{
		ServerURL:   getTestServerURL(),
		UserID:      fmt.Sprintf("test-user2-%d", time.Now().Unix()),
		Username:    "Test User 2",
		Debug:       true,
		InsecureTLS: true,
	}

	client1, err := NewClient(config1)
	if err != nil {
		t.Fatalf("Failed to create client1: %v", err)
	}
	defer client1.Disconnect()

	client2, err := NewClient(config2)
	if err != nil {
		t.Fatalf("Failed to create client2: %v", err)
	}
	defer client2.Disconnect()

	// Connect both clients
	if err := client1.Connect(); err != nil {
		t.Fatalf("Failed to connect client1: %v", err)
	}

	if err := client2.Connect(); err != nil {
		t.Fatalf("Failed to connect client2: %v", err)
	}

	// Wait for connections to stabilize
	time.Sleep(200 * time.Millisecond)

	// Set up message handler for client2
	received := make(chan *types.Message, 1)
	client2.AddMessageHandlerFunc(func(msg *types.Message) error {
		if msg.Header.From == config1.UserID {
			received <- msg
		}
		return nil
	})

	// Send message from client1 to client2
	testMessage := "Hello from integration test"
	err = client1.SendMessage(config2.UserID, testMessage, true)
	if err != nil {
		t.Fatalf("Failed to send message: %v", err)
	}

	// Wait for message
	select {
	case msg := <-received:
		if msg.Body.Content != testMessage {
			t.Errorf("Expected message '%s', got '%s'", testMessage, msg.Body.Content)
		}
		// Verify signature
		valid, err := client2.VerifyMessageSignature(msg)
		if err != nil {
			t.Errorf("Failed to verify signature: %v", err)
		}
		if !valid {
			t.Error("Message signature should be valid")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Timeout waiting for message")
	}
}

func TestIntegrationBroadcast(t *testing.T) {
	numClients := 3
	clients := make([]*Client, numClients)
	configs := make([]*Config, numClients)

	// Create clients
	for i := 0; i < numClients; i++ {
		configs[i] = &Config{
			ServerURL:   getTestServerURL(),
			UserID:      fmt.Sprintf("test-broadcast-%d-%d", i, time.Now().Unix()),
			Username:    fmt.Sprintf("Broadcast User %d", i),
			Debug:       false,
			InsecureTLS: true,
		}

		var err error
		clients[i], err = NewClient(configs[i])
		if err != nil {
			t.Fatalf("Failed to create client %d: %v", i, err)
		}
		defer clients[i].Disconnect()

		if err := clients[i].Connect(); err != nil {
			t.Fatalf("Failed to connect client %d: %v", i, err)
		}
	}

	// Wait for connections
	time.Sleep(200 * time.Millisecond)

	// Set up message handlers
	var wg sync.WaitGroup
	received := make([]int, numClients)
	var mu sync.Mutex

	for i := 1; i < numClients; i++ {
		idx := i
		wg.Add(1)
		clients[idx].AddMessageHandlerFunc(func(msg *types.Message) error {
			if msg.Header.IsBroadcast && msg.Header.From == configs[0].UserID {
				mu.Lock()
				received[idx]++
				mu.Unlock()
				wg.Done()
			}
			return nil
		})
	}

	// Send broadcast from first client
	err := clients[0].Broadcast("Test broadcast message")
	if err != nil {
		t.Fatalf("Failed to broadcast: %v", err)
	}

	// Wait for all clients to receive
	done := make(chan bool)
	go func() {
		wg.Wait()
		done <- true
	}()

	select {
	case <-done:
		// Check that all clients (except sender) received the message
		for i := 1; i < numClients; i++ {
			if received[i] != 1 {
				t.Errorf("Client %d received %d messages, expected 1", i, received[i])
			}
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Timeout waiting for broadcast messages")
	}
}

func TestIntegrationReconnection(t *testing.T) {
	config := &Config{
		ServerURL:        getTestServerURL(),
		UserID:           fmt.Sprintf("test-reconnect-%d", time.Now().Unix()),
		Username:         "Reconnect User",
		AutoReconnect:    true,
		MaxReconnectWait: 5 * time.Second,
		Debug:            true,
		InsecureTLS:      true,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Disconnect()

	// Track connection events
	connectCount := 0
	reconnected := make(chan bool, 1)
	
	client.OnConnect(func() {
		connectCount++
		t.Logf("Connection established (count: %d)", connectCount)
		if connectCount > 1 {
			// This is a reconnection
			reconnected <- true
		}
	})
	
	client.OnReconnect(func(attempt int) {
		t.Logf("Reconnection attempt %d scheduled", attempt)
	})

	// Connect initially
	if err := client.Connect(); err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}

	// Wait for initial connection to establish
	time.Sleep(100 * time.Millisecond)
	
	if !client.IsConnected() {
		t.Fatal("Client should be connected")
	}

	// Force disconnect by simulating network failure
	// Send a close message to cleanly disconnect from server's perspective
	client.connLock.Lock()
	if client.conn != nil {
		// Send close frame with normal closure code
		client.conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
		time.Sleep(100 * time.Millisecond) // Give server time to process close
		client.conn.Close()
	}
	client.connLock.Unlock()
	
	// Give the client time to detect disconnection and trigger reconnection
	time.Sleep(200 * time.Millisecond)

	// Wait for reconnection to complete (not just be scheduled)
	select {
	case <-reconnected:
		// Give a moment for state to stabilize
		time.Sleep(500 * time.Millisecond)
		if !client.IsConnected() {
			t.Error("Client should be reconnected")
		}
		t.Log("Reconnection successful")
	case <-time.After(15 * time.Second):
		t.Fatal("Timeout waiting for reconnection")
	}
}

func TestIntegrationMetrics(t *testing.T) {
	config := &Config{
		ServerURL:   getTestServerURL(),
		UserID:      fmt.Sprintf("test-metrics-%d", time.Now().Unix()),
		Username:    "Metrics User",
		Debug:       false,
		InsecureTLS: true,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Disconnect()

	if err := client.Connect(); err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}

	// Send some messages
	numMessages := 10
	for i := 0; i < numMessages; i++ {
		err := client.Broadcast(fmt.Sprintf("Message %d", i))
		if err != nil {
			t.Errorf("Failed to send message %d: %v", i, err)
		}
	}

	// Wait for messages to be processed
	time.Sleep(500 * time.Millisecond)

	// Check metrics
	sent, _, _, _ := client.GetMetrics()
	if sent < uint64(numMessages) {
		t.Errorf("Expected at least %d sent messages, got %d", numMessages, sent)
	}
}

func TestIntegrationStressTest(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}

	numClients := 10
	messagesPerClient := 50
	clients := make([]*Client, numClients)

	// Create and connect clients
	for i := 0; i < numClients; i++ {
		config := &Config{
			ServerURL:         getTestServerURL(),
			UserID:            fmt.Sprintf("stress-test-%d-%d", i, time.Now().Unix()),
			Username:          fmt.Sprintf("Stress User %d", i),
			MessageBufferSize: 100,
			Workers:           5,
			Debug:             false,
			InsecureTLS:       true,
		}

		var err error
		clients[i], err = NewClient(config)
		if err != nil {
			t.Fatalf("Failed to create client %d: %v", i, err)
		}
		defer clients[i].Disconnect()

		if err := clients[i].Connect(); err != nil {
			t.Fatalf("Failed to connect client %d: %v", i, err)
		}
	}

	// Wait for all connections
	time.Sleep(500 * time.Millisecond)

	// Send messages concurrently
	var wg sync.WaitGroup
	start := time.Now()

	for i := 0; i < numClients; i++ {
		wg.Add(1)
		go func(clientIdx int) {
			defer wg.Done()
			for j := 0; j < messagesPerClient; j++ {
				msg := fmt.Sprintf("Stress test message %d-%d", clientIdx, j)
				if err := clients[clientIdx].Broadcast(msg); err != nil {
					t.Errorf("Client %d failed to send message %d: %v", clientIdx, j, err)
				}
			}
		}(i)
	}

	wg.Wait()
	duration := time.Since(start)

	totalMessages := numClients * messagesPerClient
	rate := float64(totalMessages) / duration.Seconds()

	t.Logf("Stress test completed: %d messages in %v (%.2f msg/s)",
		totalMessages, duration, rate)

	// Verify metrics
	for i, client := range clients {
		sent, _, _, errors := client.GetMetrics()
		if sent < uint64(messagesPerClient) {
			t.Errorf("Client %d sent %d messages, expected %d", i, sent, messagesPerClient)
		}
		if errors > 0 {
			t.Errorf("Client %d had %d errors", i, errors)
		}
	}
}
