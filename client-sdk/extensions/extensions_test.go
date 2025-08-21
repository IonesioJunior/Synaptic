package extensions

import (
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/IonesioJunior/Synaptic/client-sdk/types"
)

// Test message types for testing
type TestMessage struct {
	*types.BaseExtendedMessage
	Type     string `json:"type"`
	TestData string `json:"test_data"`
}

// NewTestMessage creates a new TestMessage with initialized base
func NewTestMessage() *TestMessage {
	return &TestMessage{
		BaseExtendedMessage: &types.BaseExtendedMessage{
			Message: &types.Message{},
		},
	}
}

type AnotherTestMessage struct {
	*types.BaseExtendedMessage
	Type  string `json:"type"`
	Value int    `json:"value"`
}

// Test handler implementation
type testHandler struct {
	handled     []string
	handledMsgs []types.ExtendedMessage
	returnError bool
	mu          sync.Mutex
}

func (th *testHandler) HandleTypedMessage(msgType string, msg types.ExtendedMessage) error {
	th.mu.Lock()
	defer th.mu.Unlock()

	th.handled = append(th.handled, msgType)
	th.handledMsgs = append(th.handledMsgs, msg)

	if th.returnError {
		return errors.New("test error")
	}
	return nil
}

func (th *testHandler) GetSupportedTypes() []string {
	return []string{"TestMessage", "AnotherTestMessage"}
}

// reset clears the handler state for testing
// TODO: Use this method in tests that need to reset handler state
// func (th *testHandler) reset() {
// 	th.mu.Lock()
// 	defer th.mu.Unlock()
// 	th.handled = nil
// 	th.handledMsgs = nil
// }

func TestDefaultMessageFactory_RegisterAndCreate(t *testing.T) {
	factory := NewDefaultMessageFactory()

	// Register a test message type
	testMsg := NewTestMessage()
	testMsg.Type = "TestMessage"
	factory.RegisterType("TestMessage", testMsg)

	// Create an instance
	created, err := factory.CreateMessage("TestMessage")
	if err != nil {
		t.Fatalf("CreateMessage failed: %v", err)
	}

	// Check type
	if _, ok := created.(*TestMessage); !ok {
		t.Errorf("Created message is not of type TestMessage")
	}

	// Try to create unknown type
	_, err = factory.CreateMessage("UnknownType")
	if err == nil {
		t.Error("Expected error for unknown message type")
	}
}

func TestDefaultMessageFactory_ParseMessage(t *testing.T) {
	factory := NewDefaultMessageFactory()

	// Register test message type
	testMsg := NewTestMessage()
	factory.RegisterType("TestMessage", testMsg)

	tests := []struct {
		name    string
		data    string
		wantErr bool
	}{
		{
			name:    "valid TestMessage",
			data:    `{"type": "TestMessage", "test_data": "hello"}`,
			wantErr: false,
		},
		{
			name:    "missing type",
			data:    `{"test_data": "hello"}`,
			wantErr: true,
		},
		{
			name:    "unknown type",
			data:    `{"type": "UnknownType", "test_data": "hello"}`,
			wantErr: true,
		},
		{
			name:    "invalid json",
			data:    `{invalid json}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg, err := factory.ParseMessage([]byte(tt.data))
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseMessage() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && msg == nil {
				t.Error("Expected non-nil message")
			}
		})
	}
}

func TestMessageRouter_HandleMessage(t *testing.T) {
	router := NewMessageRouter()

	// Create and register handler for basic messages
	handler := &testHandler{}
	router.RegisterHandler("*", handler)

	// Create a basic message (will use handleBasicMessage path)
	baseMsg := &types.Message{
		Header: types.MessageHeader{
			From: "user1",
			To:   "user2",
		},
		Body: types.MessageBody{
			Content: "Plain text message",
		},
	}

	// Handle the message
	err := router.HandleMessage(baseMsg)
	if err != nil {
		t.Fatalf("HandleMessage failed: %v", err)
	}

	// Verify handler was called with basic type
	if len(handler.handled) != 1 {
		t.Errorf("Expected 1 handled message, got %d", len(handler.handled))
	}
	if len(handler.handled) > 0 && handler.handled[0] != "basic" {
		t.Errorf("Expected message type 'basic', got %s", handler.handled[0])
	}
}

func TestMessageRouter_HandleBasicMessage(t *testing.T) {
	router := NewMessageRouter()

	// Register a wildcard handler
	handler := &testHandler{}
	router.RegisterHandler("*", handler)

	// Create a basic message (non-parseable as extended)
	baseMsg := &types.Message{
		Header: types.MessageHeader{
			From: "user1",
			To:   "user2",
		},
		Body: types.MessageBody{
			Content: "Plain text message",
		},
	}

	// Handle the message
	err := router.HandleMessage(baseMsg)
	if err != nil {
		t.Fatalf("HandleMessage failed: %v", err)
	}

	// Verify wildcard handler was called with "basic" type
	if len(handler.handled) != 1 {
		t.Errorf("Expected 1 handled message, got %d", len(handler.handled))
	}
	if handler.handled[0] != "basic" {
		t.Errorf("Expected message type 'basic', got %s", handler.handled[0])
	}
}

func TestMessageRouter_HandlerError(t *testing.T) {
	router := NewMessageRouter()

	// Create handler that returns error for basic messages
	handler := &testHandler{returnError: true}
	router.RegisterHandler("*", handler)

	// Create a basic message
	baseMsg := &types.Message{
		Header: types.MessageHeader{From: "user1", To: "user2"},
		Body:   types.MessageBody{Content: "test message"},
	}

	// Handle should return error
	err := router.HandleMessage(baseMsg)
	if err == nil {
		t.Error("Expected error from handler")
	}
}

func TestChainedHandler(t *testing.T) {
	chained := NewChainedHandler()

	// Track handler calls
	var calls []int
	var mu sync.Mutex

	// Add multiple handlers
	for i := 1; i <= 3; i++ {
		idx := i
		chained.AddHandler(types.MessageHandlerFunc(func(msg *types.Message) error {
			mu.Lock()
			calls = append(calls, idx)
			mu.Unlock()
			return nil
		}))
	}

	// Handle a message
	msg := &types.Message{
		Header: types.MessageHeader{From: "test", To: "test"},
		Body:   types.MessageBody{Content: "test"},
	}

	err := chained.HandleMessage(msg)
	if err != nil {
		t.Fatalf("HandleMessage failed: %v", err)
	}

	// Verify all handlers were called in order
	if !reflect.DeepEqual(calls, []int{1, 2, 3}) {
		t.Errorf("Handlers called in wrong order: %v", calls)
	}
}

func TestChainedHandler_StopsOnError(t *testing.T) {
	chained := NewChainedHandler()

	var calls []int

	// First handler succeeds
	chained.AddHandler(types.MessageHandlerFunc(func(msg *types.Message) error {
		calls = append(calls, 1)
		return nil
	}))

	// Second handler returns error
	chained.AddHandler(types.MessageHandlerFunc(func(msg *types.Message) error {
		calls = append(calls, 2)
		return errors.New("stop here")
	}))

	// Third handler should not be called
	chained.AddHandler(types.MessageHandlerFunc(func(msg *types.Message) error {
		calls = append(calls, 3)
		return nil
	}))

	msg := &types.Message{
		Header: types.MessageHeader{From: "test", To: "test"},
		Body:   types.MessageBody{Content: "test"},
	}

	err := chained.HandleMessage(msg)
	if err == nil {
		t.Error("Expected error from second handler")
	}

	// Only first two handlers should have been called
	if !reflect.DeepEqual(calls, []int{1, 2}) {
		t.Errorf("Expected calls [1, 2], got %v", calls)
	}
}

func TestFilteredHandler(t *testing.T) {
	var handled []*types.Message

	// Create handler that tracks messages
	innerHandler := types.MessageHandlerFunc(func(msg *types.Message) error {
		handled = append(handled, msg)
		return nil
	})

	// Create filter that only accepts messages to "user2"
	filter := func(msg *types.Message) bool {
		return msg.Header.To == "user2"
	}

	filtered := NewFilteredHandler(filter, innerHandler)

	// Test messages
	msg1 := &types.Message{
		Header: types.MessageHeader{From: "user1", To: "user2"},
		Body:   types.MessageBody{Content: "should pass"},
	}

	msg2 := &types.Message{
		Header: types.MessageHeader{From: "user1", To: "user3"},
		Body:   types.MessageBody{Content: "should not pass"},
	}

	// Handle messages
	filtered.HandleMessage(msg1)
	filtered.HandleMessage(msg2)

	// Only msg1 should have been handled
	if len(handled) != 1 {
		t.Errorf("Expected 1 handled message, got %d", len(handled))
	}
	if len(handled) > 0 && handled[0] != msg1 {
		t.Error("Wrong message was handled")
	}
}

func TestAsyncHandler(t *testing.T) {
	handled := make(chan *types.Message, 10)

	// Create handler that sends to channel
	innerHandler := types.MessageHandlerFunc(func(msg *types.Message) error {
		handled <- msg
		return nil
	})

	// Create async handler with small queue
	async := NewAsyncHandler(innerHandler, 5, 2)
	defer async.Stop()

	// Send multiple messages
	for i := 0; i < 3; i++ {
		msg := &types.Message{
			ID:     i,
			Header: types.MessageHeader{From: "test", To: "test"},
			Body:   types.MessageBody{Content: "async test"},
		}
		err := async.HandleMessage(msg)
		if err != nil {
			t.Errorf("Failed to handle message %d: %v", i, err)
		}
	}

	// Wait for all messages to be handled
	timeout := time.After(2 * time.Second)
	receivedCount := 0

	for receivedCount < 3 {
		select {
		case <-handled:
			receivedCount++
		case <-timeout:
			t.Fatalf("Timeout waiting for messages, received %d/3", receivedCount)
		}
	}
}

func TestAsyncHandler_QueueFull(t *testing.T) {
	// Create handler that blocks indefinitely
	blockChan := make(chan struct{})
	processStarted := make(chan struct{}, 1)
	innerHandler := types.MessageHandlerFunc(func(msg *types.Message) error {
		select {
		case processStarted <- struct{}{}:
		default:
		}
		<-blockChan
		return nil
	})

	// Create async handler with tiny queue (size 2) and 1 worker
	async := NewAsyncHandler(innerHandler, 2, 1)
	defer func() {
		close(blockChan)
		async.Stop()
	}()

	// Fill the queue
	msg := &types.Message{
		Header: types.MessageHeader{From: "test", To: "test"},
		Body:   types.MessageBody{Content: "test"},
	}

	// Send first message - it will be picked up by the worker and block
	err := async.HandleMessage(msg)
	if err != nil {
		t.Errorf("First message should have been queued: %v", err)
	}

	// Wait for worker to start processing
	<-processStarted

	// Now fill the queue (size is 2)
	for i := 0; i < 2; i++ {
		err := async.HandleMessage(msg)
		if err != nil {
			t.Errorf("Message %d should have been queued: %v", i+1, err)
		}
	}

	// Queue should be full now (worker blocked on 1st msg, 2 msgs in queue)
	// This should fail
	err = async.HandleMessage(msg)
	if err == nil {
		t.Error("Expected error when queue is full")
	}
}

func TestAsyncHandler_Stop(t *testing.T) {
	handledCount := 0
	var mu sync.Mutex

	innerHandler := types.MessageHandlerFunc(func(msg *types.Message) error {
		mu.Lock()
		handledCount++
		mu.Unlock()
		return nil
	})

	async := NewAsyncHandler(innerHandler, 10, 2)

	// Send some messages
	for i := 0; i < 5; i++ {
		msg := &types.Message{
			Header: types.MessageHeader{From: "test", To: "test"},
			Body:   types.MessageBody{Content: "test"},
		}
		err := async.HandleMessage(msg)
		if err != nil {
			t.Errorf("Failed to queue message %d: %v", i, err)
		}
	}

	// Give workers time to process messages
	time.Sleep(100 * time.Millisecond)

	// Stop the handler (should wait for workers to finish)
	async.Stop()

	// Check that all messages were handled
	mu.Lock()
	count := handledCount
	mu.Unlock()

	if count != 5 {
		t.Errorf("Expected 5 messages handled, got %d", count)
	}
}

func TestMessageRouter_ConcurrentAccess(t *testing.T) {
	router := NewMessageRouter()
	factory := NewDefaultMessageFactory()

	// Register the TestMessage type with proper initialization
	testMsg := &TestMessage{
		BaseExtendedMessage: &types.BaseExtendedMessage{
			Message: &types.Message{},
		},
		Type: "TestMessage",
	}
	factory.RegisterType("TestMessage", testMsg)
	router.SetFactory(factory)

	// Concurrently register handlers and handle messages
	var wg sync.WaitGroup

	// Register handlers concurrently
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			handler := &testHandler{}
			router.RegisterHandler("TestMessage", handler)
		}(i)
	}

	// Wait for handlers to be registered
	wg.Wait()

	// Handle messages concurrently
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			msg := &types.Message{
				Header: types.MessageHeader{From: "user", To: "user"},
				Body:   types.MessageBody{Content: `{"type": "TestMessage", "test_data": "concurrent"}`},
			}
			router.HandleMessage(msg)
		}(i)
	}

	wg.Wait()
}

func TestDefaultMessageFactory_ConcurrentRegister(t *testing.T) {
	factory := NewDefaultMessageFactory()

	var wg sync.WaitGroup

	// Register types concurrently
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			msgType := NewTestMessage()
			factory.RegisterType("TestMessage", msgType)
		}(i)
	}

	wg.Wait()

	// Verify type is registered
	msg, err := factory.CreateMessage("TestMessage")
	if err != nil {
		t.Errorf("Failed to create message after concurrent registration: %v", err)
	}
	if msg == nil {
		t.Error("Created message is nil")
	}
}

func BenchmarkMessageRouter_HandleMessage(b *testing.B) {
	router := NewMessageRouter()
	factory := NewDefaultMessageFactory()

	testMsg := NewTestMessage()
	factory.RegisterType("TestMessage", testMsg)
	router.SetFactory(factory)

	handler := &testHandler{}
	router.RegisterHandler("TestMessage", handler)

	msg := &types.Message{
		Header: types.MessageHeader{From: "user1", To: "user2"},
		Body:   types.MessageBody{Content: `{"type": "TestMessage", "test_data": "benchmark"}`},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		router.HandleMessage(msg)
	}
}

func BenchmarkAsyncHandler(b *testing.B) {
	handler := types.MessageHandlerFunc(func(msg *types.Message) error {
		// Simulate some work
		time.Sleep(time.Microsecond)
		return nil
	})

	async := NewAsyncHandler(handler, 1000, 10)
	defer async.Stop()

	msg := &types.Message{
		Header: types.MessageHeader{From: "test", To: "test"},
		Body:   types.MessageBody{Content: "benchmark"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		async.HandleMessage(msg)
	}
}

func BenchmarkChainedHandler(b *testing.B) {
	chained := NewChainedHandler()

	// Add 5 handlers
	for i := 0; i < 5; i++ {
		chained.AddHandler(types.MessageHandlerFunc(func(msg *types.Message) error {
			return nil
		}))
	}

	msg := &types.Message{
		Header: types.MessageHeader{From: "test", To: "test"},
		Body:   types.MessageBody{Content: "benchmark"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		chained.HandleMessage(msg)
	}
}
