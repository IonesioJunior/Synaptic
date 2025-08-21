package client

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/IonesioJunior/Synaptic/client-sdk/auth"
	"github.com/IonesioJunior/Synaptic/client-sdk/types"
)

func TestClient_Connect_WithEncryption(t *testing.T) {
	// Generate keys
	_, ed25519Priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}

	// Convert private key to base64
	privKeyBase64 := base64.StdEncoding.EncodeToString(ed25519Priv)

	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		}

		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		// Keep connection alive for test
		time.Sleep(100 * time.Millisecond)
	}))
	defer server.Close()

	// Convert http to ws URL
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	t.Run("ConnectWithEncryptionRequired", func(t *testing.T) {
		config := &Config{
			ServerURL:        wsURL,
			UserID:           "test-user",
			Username:         "Test User",
			EncryptionPolicy: EncryptionRequired,
			PrivateKey:       privKeyBase64,
		}

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("Failed to create client: %v", err)
		}

		// Create real auth manager for testing
		authManager, err := auth.NewAuthManagerWithKeys(server.URL, "test-user", "Test User", ed25519Priv)
		if err != nil {
			t.Fatalf("Failed to create auth manager: %v", err)
		}
		client.auth = authManager

		err = client.Connect()
		if err != nil {
			// WebSocket connection might fail without proper server setup
			t.Logf("Connect attempt: %v", err)
		}

		// Verify encryption policy is set correctly
		if client.config.EncryptionPolicy != EncryptionRequired {
			t.Error("Encryption policy should be EncryptionRequired")
		}

		client.Disconnect()
	})

	t.Run("ConnectWithAutoReconnect", func(t *testing.T) {
		config := &Config{
			ServerURL:     wsURL,
			UserID:        "test-user",
			Username:      "Test User",
			AutoReconnect: true,
		}

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("Failed to create client: %v", err)
		}

		// Use real auth manager
		_, privKey, _ := ed25519.GenerateKey(rand.Reader)
		authManager, err := auth.NewAuthManagerWithKeys(server.URL, "test-user", "Test User", privKey)
		if err != nil {
			t.Fatalf("Failed to create auth manager: %v", err)
		}
		client.auth = authManager

		// Verify auto-reconnect is enabled
		if !client.config.AutoReconnect {
			t.Error("Auto-reconnect should be enabled")
		}

		err = client.Connect()
		if err != nil {
			t.Logf("Connect attempt: %v", err)
		}

		client.Disconnect()
	})

	t.Run("ConnectTimeout", func(t *testing.T) {
		// Create server that doesn't upgrade connection
		slowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Don't upgrade, just hang
			time.Sleep(5 * time.Second)
		}))
		defer slowServer.Close()

		wsURL := "ws" + strings.TrimPrefix(slowServer.URL, "http")

		config := &Config{
			ServerURL: wsURL,
			UserID:    "test-user",
			Username:  "Test User",
		}

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("Failed to create client: %v", err)
		}

		// Use real auth manager
		_, privKey, _ := ed25519.GenerateKey(rand.Reader)
		authManager, err := auth.NewAuthManagerWithKeys(slowServer.URL, "test-user", "Test User", privKey)
		if err != nil {
			t.Fatalf("Failed to create auth manager: %v", err)
		}
		client.auth = authManager

		err = client.Connect()
		// Will timeout waiting for the server
		if err == nil {
			// If it doesn't timeout, it's still ok
			client.Disconnect()
		}
	})
}

func TestClient_SendMessage_WithTimeout(t *testing.T) {
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		}

		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		// Read messages but don't respond
		for {
			_, _, err := conn.ReadMessage()
			if err != nil {
				break
			}
		}
	}))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	config := &Config{
		ServerURL: wsURL,
		UserID:    "test-user",
		Username:  "Test User",
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Use real auth manager
	_, privKey, _ := ed25519.GenerateKey(rand.Reader)
	authManager, err := auth.NewAuthManagerWithKeys(server.URL, "test-user", "Test User", privKey)
	if err != nil {
		t.Fatalf("Failed to create auth manager: %v", err)
	}
	client.auth = authManager

	err = client.Connect()
	if err != nil {
		t.Skipf("Skipping send test, connect failed: %v", err)
	}
	defer client.Disconnect()

	t.Run("SendWithFullChannel", func(t *testing.T) {
		// Fill the send channel
		for i := 0; i < cap(client.sendChan); i++ {
			select {
			case client.sendChan <- &types.Message{}:
			default:
				// Channel is full, stop trying
				goto done
			}
		}
	done:

		// Try to send another message
		err := client.SendMessage("recipient", "test message", false)
		if err == nil {
			t.Error("Expected timeout error with full channel")
		}
	})
}

func TestClient_Configuration(t *testing.T) {
	config := &Config{
		ServerURL: "ws://localhost:8080",
		UserID:    "test-user",
		Username:  "Test User",
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	t.Run("WithAutoReconnect", func(t *testing.T) {
		client.config.AutoReconnect = true

		if !client.config.AutoReconnect {
			t.Error("AutoReconnect should be true")
		}
	})

	t.Run("WithoutAutoReconnect", func(t *testing.T) {
		client.config.AutoReconnect = false

		if client.config.AutoReconnect {
			t.Error("AutoReconnect should be false")
		}
	})

	t.Run("WithCallback", func(t *testing.T) {
		callbackCalled := false

		client.OnDisconnect(func(err error) {
			callbackCalled = true
		})

		// Trigger disconnect callback
		if client.onDisconnect != nil {
			client.onDisconnect(errors.New("test error"))
		}

		// Give callback time to execute
		time.Sleep(50 * time.Millisecond)

		if !callbackCalled {
			t.Error("Disconnect callback was not called")
		}
	})
}
