package client

import (
	"crypto/ed25519"
	"encoding/base64"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/genericwsserver/client-sdk/types"
)

func TestClientCreation(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name: "valid config",
			config: &Config{
				ServerURL: "http://localhost:8080",
				UserID:    "test-user",
				Username:  "Test User",
			},
			wantErr: false,
		},
		{
			name: "missing server URL",
			config: &Config{
				UserID:   "test-user",
				Username: "Test User",
			},
			wantErr: true,
		},
		{
			name: "with private key",
			config: &Config{
				ServerURL:  "http://localhost:8080",
				UserID:     "test-user",
				Username:   "Test User",
				PrivateKey: generateTestPrivateKey(),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewClient() error = %v, wantErr %v", err, tt.wantErr)
			}
			if client != nil {
				client.Disconnect()
			}
		})
	}
}

func TestMessageHandling(t *testing.T) {
	config := &Config{
		ServerURL:         "http://localhost:8080",
		UserID:            "test-user",
		Username:          "Test User",
		MessageBufferSize: 10,
		Workers:           2,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Disconnect()

	var receivedCount atomic.Int32
	var mu sync.Mutex
	receivedMessages := make([]*types.Message, 0)

	client.AddMessageHandlerFunc(func(msg *types.Message) error {
		mu.Lock()
		receivedMessages = append(receivedMessages, msg)
		mu.Unlock()
		receivedCount.Add(1)
		return nil
	})

	testMsg := &types.Message{
		Header: types.MessageHeader{
			From:      "sender",
			To:        "test-user",
			Timestamp: time.Now(),
		},
		Body: types.MessageBody{
			Content: "Test message",
		},
	}

	client.processMessage(testMsg)

	time.Sleep(100 * time.Millisecond)

	if receivedCount.Load() != 1 {
		t.Errorf("Expected 1 message, got %d", receivedCount.Load())
	}

	mu.Lock()
	if len(receivedMessages) != 1 {
		t.Errorf("Expected 1 message in slice, got %d", len(receivedMessages))
	}
	if len(receivedMessages) > 0 && receivedMessages[0].Body.Content != "Test message" {
		t.Errorf("Expected message content 'Test message', got '%s'", receivedMessages[0].Body.Content)
	}
	mu.Unlock()
}

func TestConcurrentMessageProcessing(t *testing.T) {
	config := &Config{
		ServerURL:         "http://localhost:8080",
		UserID:            "test-user",
		Username:          "Test User",
		MessageBufferSize: 100,
		Workers:           5,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Disconnect()

	var processedCount atomic.Int32
	var wg sync.WaitGroup

	client.AddMessageHandlerFunc(func(msg *types.Message) error {
		time.Sleep(10 * time.Millisecond)
		processedCount.Add(1)
		wg.Done()
		return nil
	})

	numMessages := 20
	wg.Add(numMessages)

	for i := 0; i < numMessages; i++ {
		go func(i int) {
			msg := &types.Message{
				Header: types.MessageHeader{
					From:      "sender",
					To:        "test-user",
					Timestamp: time.Now(),
				},
				Body: types.MessageBody{
					Content: "Test message",
				},
			}
			client.processMessage(msg)
		}(i)
	}

	done := make(chan bool)
	go func() {
		wg.Wait()
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Timeout waiting for messages to be processed")
	}

	if processedCount.Load() != int32(numMessages) {
		t.Errorf("Expected %d messages processed, got %d", numMessages, processedCount.Load())
	}
}

func TestStateTransitions(t *testing.T) {
	config := &Config{
		ServerURL: "http://localhost:8080",
		UserID:    "test-user",
		Username:  "Test User",
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Disconnect()

	if client.GetState() != types.StateDisconnected {
		t.Errorf("Initial state should be Disconnected, got %v", client.GetState())
	}

	client.setState(types.StateConnecting)
	if client.GetState() != types.StateConnecting {
		t.Errorf("State should be Connecting, got %v", client.GetState())
	}

	client.setState(types.StateConnected)
	if client.GetState() != types.StateConnected {
		t.Errorf("State should be Connected, got %v", client.GetState())
	}
	if !client.IsConnected() {
		t.Error("IsConnected() should return true when state is Connected")
	}

	client.setState(types.StateReconnecting)
	if client.GetState() != types.StateReconnecting {
		t.Errorf("State should be Reconnecting, got %v", client.GetState())
	}
	if client.IsConnected() {
		t.Error("IsConnected() should return false when state is not Connected")
	}
}

func TestMetrics(t *testing.T) {
	config := &Config{
		ServerURL: "http://localhost:8080",
		UserID:    "test-user",
		Username:  "Test User",
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Disconnect()

	client.metrics.messagesSent.Add(5)
	client.metrics.messagesReceived.Add(10)
	client.metrics.reconnectCount.Add(2)
	client.metrics.errorsCount.Add(1)

	sent, received, reconnects, errors := client.GetMetrics()

	if sent != 5 {
		t.Errorf("Expected 5 sent messages, got %d", sent)
	}
	if received != 10 {
		t.Errorf("Expected 10 received messages, got %d", received)
	}
	if reconnects != 2 {
		t.Errorf("Expected 2 reconnects, got %d", reconnects)
	}
	if errors != 1 {
		t.Errorf("Expected 1 error, got %d", errors)
	}
}

func TestChannelOperations(t *testing.T) {
	config := &Config{
		ServerURL:         "http://localhost:8080",
		UserID:            "test-user",
		Username:          "Test User",
		MessageBufferSize: 2,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Disconnect()

	recvChan := client.GetReceiveChannel()
	errChan := client.GetErrorChannel()

	if recvChan == nil {
		t.Error("Receive channel should not be nil")
	}
	if errChan == nil {
		t.Error("Error channel should not be nil")
	}

	testMsg := &types.Message{
		Header: types.MessageHeader{
			From:      "sender",
			To:        "test-user",
			Timestamp: time.Now(),
		},
		Body: types.MessageBody{
			Content: "Test",
		},
	}

	select {
	case client.receiveChan <- testMsg:
	case <-time.After(1 * time.Second):
		t.Error("Failed to send message to receive channel")
	}

	select {
	case msg := <-recvChan:
		if msg.Body.Content != "Test" {
			t.Errorf("Expected content 'Test', got '%s'", msg.Body.Content)
		}
	case <-time.After(1 * time.Second):
		t.Error("Failed to receive message from channel")
	}
}

func TestCallbacks(t *testing.T) {
	config := &Config{
		ServerURL: "http://localhost:8080",
		UserID:    "test-user",
		Username:  "Test User",
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Disconnect()

	var connectCalled, disconnectCalled, reconnectCalled bool
	var reconnectAttempt int

	client.OnConnect(func() {
		connectCalled = true
	})

	client.OnDisconnect(func(err error) {
		disconnectCalled = true
	})

	client.OnReconnect(func(attempt int) {
		reconnectCalled = true
		reconnectAttempt = attempt
	})

	if client.onConnect == nil {
		t.Error("OnConnect callback not set")
	}
	if client.onDisconnect == nil {
		t.Error("OnDisconnect callback not set")
	}
	if client.onReconnect == nil {
		t.Error("OnReconnect callback not set")
	}

	client.onConnect()
	client.onDisconnect(nil)
	client.onReconnect(3)

	time.Sleep(50 * time.Millisecond)

	if !connectCalled {
		t.Error("Connect callback not called")
	}
	if !disconnectCalled {
		t.Error("Disconnect callback not called")
	}
	if !reconnectCalled {
		t.Error("Reconnect callback not called")
	}
	if reconnectAttempt != 3 {
		t.Errorf("Expected reconnect attempt 3, got %d", reconnectAttempt)
	}
}

func TestWorkerPool(t *testing.T) {
	config := &Config{
		ServerURL: "http://localhost:8080",
		UserID:    "test-user",
		Username:  "Test User",
		Workers:   3,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Disconnect()

	availableWorkers := 0
	for i := 0; i < config.Workers; i++ {
		select {
		case <-client.workerPool:
			availableWorkers++
		default:
		}
	}

	if availableWorkers != config.Workers {
		t.Errorf("Expected %d workers in pool, got %d", config.Workers, availableWorkers)
	}

	for i := 0; i < availableWorkers; i++ {
		client.workerPool <- struct{}{}
	}
}

func TestContextCancellation(t *testing.T) {
	config := &Config{
		ServerURL: "http://localhost:8080",
		UserID:    "test-user",
		Username:  "Test User",
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx := client.ctx

	client.Disconnect()

	select {
	case <-ctx.Done():
	case <-time.After(1 * time.Second):
		t.Error("Context not cancelled after disconnect")
	}
}

func generateTestPrivateKey() string {
	_, priv, _ := ed25519.GenerateKey(nil)
	return base64.StdEncoding.EncodeToString(priv)
}

func BenchmarkMessageProcessing(b *testing.B) {
	config := &Config{
		ServerURL:         "http://localhost:8080",
		UserID:            "test-user",
		Username:          "Test User",
		MessageBufferSize: 1000,
		Workers:           10,
	}

	client, err := NewClient(config)
	if err != nil {
		b.Fatalf("Failed to create client: %v", err)
	}
	defer client.Disconnect()

	client.AddMessageHandlerFunc(func(msg *types.Message) error {
		return nil
	})

	msg := &types.Message{
		Header: types.MessageHeader{
			From:      "sender",
			To:        "test-user",
			Timestamp: time.Now(),
		},
		Body: types.MessageBody{
			Content: "Benchmark message",
		},
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		client.processMessage(msg)
	}
}

func BenchmarkConcurrentMessageProcessing(b *testing.B) {
	config := &Config{
		ServerURL:         "http://localhost:8080",
		UserID:            "test-user",
		Username:          "Test User",
		MessageBufferSize: 1000,
		Workers:           10,
	}

	client, err := NewClient(config)
	if err != nil {
		b.Fatalf("Failed to create client: %v", err)
	}
	defer client.Disconnect()

	client.AddMessageHandlerFunc(func(msg *types.Message) error {
		return nil
	})

	msg := &types.Message{
		Header: types.MessageHeader{
			From:      "sender",
			To:        "test-user",
			Timestamp: time.Now(),
		},
		Body: types.MessageBody{
			Content: "Benchmark message",
		},
	}

	b.ResetTimer()

	var wg sync.WaitGroup
	for i := 0; i < b.N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client.processMessage(msg)
		}()
	}
	wg.Wait()
}
