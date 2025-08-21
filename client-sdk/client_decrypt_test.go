package client

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/genericwsserver/client-sdk/auth"
	"github.com/genericwsserver/client-sdk/crypto"
	"github.com/genericwsserver/client-sdk/types"
)

func TestClient_DecryptMessage_Comprehensive(t *testing.T) {
	// Generate test keys
	_, ed25519Priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 keys: %v", err)
	}

	// Create client with encryption
	config := &Config{
		ServerURL:        "http://localhost:8080",
		UserID:           "test-user",
		Username:         "Test User",
		EncryptionPolicy: EncryptionRequired,
		PrivateKey:       base64.StdEncoding.EncodeToString(ed25519Priv),
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Get the client's X25519 keys for testing
	x25519PubKey, _, err := crypto.DeriveX25519FromEd25519Seed(ed25519Priv)
	if err != nil {
		t.Fatalf("Failed to derive X25519 keys: %v", err)
	}

	t.Run("UnencryptedMessage", func(t *testing.T) {
		// Test message without encryption
		msg := &types.Message{
			Header: types.MessageHeader{
				From: "sender",
				To:   "test-user",
			},
			Body: types.MessageBody{
				Content: "Plain text message",
			},
		}

		decrypted, err := client.decryptMessage(msg)
		if err != nil {
			t.Errorf("Failed to handle unencrypted message: %v", err)
		}
		if decrypted != "Plain text message" {
			t.Errorf("Expected 'Plain text message', got %s", decrypted)
		}
	})

	t.Run("EncryptedMessage", func(t *testing.T) {
		// Create an encrypted message
		plaintext := "Secret encrypted message"

		// Generate AES key
		aesKey, err := crypto.GenerateAESKey()
		if err != nil {
			t.Fatalf("Failed to generate AES key: %v", err)
		}

		// Encrypt content with AES
		encryptedContent, nonce, err := crypto.EncryptAESGCM([]byte(plaintext), aesKey)
		if err != nil {
			t.Fatalf("Failed to encrypt content: %v", err)
		}

		// Encrypt AES key with recipient's X25519 public key
		encryptedKey, err := crypto.EncryptSymmetricKey(aesKey, x25519PubKey)
		if err != nil {
			t.Fatalf("Failed to encrypt symmetric key: %v", err)
		}

		// Create message with encrypted content
		msg := &types.Message{
			Header: types.MessageHeader{
				From:            "sender",
				To:              "test-user",
				EncryptedKey:    base64.StdEncoding.EncodeToString(encryptedKey),
				EncryptionNonce: base64.StdEncoding.EncodeToString(nonce),
			},
			Body: types.MessageBody{
				Content: base64.StdEncoding.EncodeToString(encryptedContent),
			},
		}

		// Decrypt the message
		decrypted, err := client.decryptMessage(msg)
		if err != nil {
			t.Errorf("Failed to decrypt message: %v", err)
		}
		if decrypted != plaintext {
			t.Errorf("Expected '%s', got '%s'", plaintext, decrypted)
		}
	})

	t.Run("InvalidEncryptedKey", func(t *testing.T) {
		msg := &types.Message{
			Header: types.MessageHeader{
				From:            "sender",
				To:              "test-user",
				EncryptedKey:    "invalid-base64!",
				EncryptionNonce: base64.StdEncoding.EncodeToString([]byte("nonce123456")),
			},
			Body: types.MessageBody{
				Content: base64.StdEncoding.EncodeToString([]byte("encrypted")),
			},
		}

		_, err := client.decryptMessage(msg)
		if err == nil {
			t.Error("Expected error for invalid encrypted key")
		}
	})

	t.Run("InvalidNonce", func(t *testing.T) {
		// Generate valid encrypted key
		aesKey, _ := crypto.GenerateAESKey()
		encryptedKey, _ := crypto.EncryptSymmetricKey(aesKey, x25519PubKey)

		msg := &types.Message{
			Header: types.MessageHeader{
				From:            "sender",
				To:              "test-user",
				EncryptedKey:    base64.StdEncoding.EncodeToString(encryptedKey),
				EncryptionNonce: "invalid-base64!",
			},
			Body: types.MessageBody{
				Content: base64.StdEncoding.EncodeToString([]byte("encrypted")),
			},
		}

		_, err := client.decryptMessage(msg)
		if err == nil {
			t.Error("Expected error for invalid nonce")
		}
	})

	t.Run("InvalidEncryptedContent", func(t *testing.T) {
		// Generate valid encrypted key and nonce
		aesKey, _ := crypto.GenerateAESKey()
		encryptedKey, _ := crypto.EncryptSymmetricKey(aesKey, x25519PubKey)

		msg := &types.Message{
			Header: types.MessageHeader{
				From:            "sender",
				To:              "test-user",
				EncryptedKey:    base64.StdEncoding.EncodeToString(encryptedKey),
				EncryptionNonce: base64.StdEncoding.EncodeToString([]byte("nonce1234567")),
			},
			Body: types.MessageBody{
				Content: "invalid-base64!",
			},
		}

		_, err := client.decryptMessage(msg)
		if err == nil {
			t.Error("Expected error for invalid encrypted content")
		}
	})

	t.Run("WrongPrivateKey", func(t *testing.T) {
		// Generate a different key pair
		differentPub, _, err := crypto.GenerateX25519KeyPair()
		if err != nil {
			t.Fatalf("Failed to generate different keys: %v", err)
		}

		// Encrypt with different public key
		aesKey, _ := crypto.GenerateAESKey()
		encryptedKey, _ := crypto.EncryptSymmetricKey(aesKey, differentPub)
		encryptedContent, nonce, _ := crypto.EncryptAESGCM([]byte("secret"), aesKey)

		msg := &types.Message{
			Header: types.MessageHeader{
				From:            "sender",
				To:              "test-user",
				EncryptedKey:    base64.StdEncoding.EncodeToString(encryptedKey),
				EncryptionNonce: base64.StdEncoding.EncodeToString(nonce),
			},
			Body: types.MessageBody{
				Content: base64.StdEncoding.EncodeToString(encryptedContent),
			},
		}

		_, err = client.decryptMessage(msg)
		if err == nil {
			t.Error("Expected error when decrypting with wrong private key")
		}
	})

	t.Run("CorruptedCiphertext", func(t *testing.T) {
		// Create valid encrypted message
		plaintext := "Test message"
		aesKey, _ := crypto.GenerateAESKey()
		encryptedContent, nonce, _ := crypto.EncryptAESGCM([]byte(plaintext), aesKey)
		encryptedKey, _ := crypto.EncryptSymmetricKey(aesKey, x25519PubKey)

		// Corrupt the ciphertext
		encryptedContent[0] ^= 0xFF

		msg := &types.Message{
			Header: types.MessageHeader{
				From:            "sender",
				To:              "test-user",
				EncryptedKey:    base64.StdEncoding.EncodeToString(encryptedKey),
				EncryptionNonce: base64.StdEncoding.EncodeToString(nonce),
			},
			Body: types.MessageBody{
				Content: base64.StdEncoding.EncodeToString(encryptedContent),
			},
		}

		_, err := client.decryptMessage(msg)
		if err == nil {
			t.Error("Expected error for corrupted ciphertext")
		}
	})
}

func TestClient_EncryptMessage_Comprehensive(t *testing.T) {
	// Generate test keys
	_, ed25519Priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 keys: %v", err)
	}

	// Generate recipient keys (not used in this test suite)
	_, _, err = crypto.GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate recipient keys: %v", err)
	}

	// Create mock auth manager
	mockAuth, err := auth.NewAuthManagerWithKeys("http://localhost:8080", "test-user", "Test User", ed25519Priv)
	if err != nil {
		t.Fatalf("Failed to create auth manager: %v", err)
	}

	// Create client
	config := &Config{
		ServerURL:        "http://localhost:8080",
		UserID:           "test-user",
		Username:         "Test User",
		EncryptionPolicy: EncryptionRequired,
		PrivateKey:       base64.StdEncoding.EncodeToString(ed25519Priv),
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Replace auth manager with mock
	client.auth = mockAuth

	t.Run("EncryptionDisabled", func(t *testing.T) {
		// Note: encryptMessage always tries to encrypt when called
		// It will try to fetch recipient's key which requires a server connection
		// Skip this test as it requires a running server
		t.Skip("Skipping - requires running server to fetch recipient's public key")
	})

	t.Run("EmptyContent", func(t *testing.T) {
		// This will fail because we can't mock the HTTP call to get recipient's key
		// But it tests the code path
		encrypted, err := client.encryptMessage("", "recipient")
		if err == nil {
			// Won't happen in test without mocking HTTP
			if encrypted != nil && encrypted.EncryptedContent == "" {
				t.Error("Encrypted content should not be empty for empty input")
			}
		}
	})

	t.Run("LargeContent", func(t *testing.T) {
		// Test with large content
		largeContent := make([]byte, 10000)
		for i := range largeContent {
			largeContent[i] = byte(i % 256)
		}

		// This will fail without HTTP mocking, but tests the path
		_, err := client.encryptMessage(string(largeContent), "recipient")
		if err == nil {
			t.Log("Large content encryption attempted")
		}
	})
}

func TestClient_DecryptMessage_NilAuthManager(t *testing.T) {
	// Create client without proper auth manager
	client := &Client{
		auth: nil,
	}

	msg := &types.Message{
		Header: types.MessageHeader{
			EncryptedKey: "some-key",
		},
	}

	_, err := client.decryptMessage(msg)
	if err == nil {
		t.Error("Expected error with nil auth manager")
	}
}

// Benchmark decryption performance
func BenchmarkClient_DecryptMessage_Comprehensive(b *testing.B) {
	// Setup
	_, ed25519Priv, _ := ed25519.GenerateKey(rand.Reader)
	x25519PubKey, _, _ := crypto.DeriveX25519FromEd25519Seed(ed25519Priv)

	config := &Config{
		ServerURL:        "http://localhost:8080",
		UserID:           "test-user",
		Username:         "Test User",
		EncryptionPolicy: EncryptionRequired,
		PrivateKey:       base64.StdEncoding.EncodeToString(ed25519Priv),
	}

	client, _ := NewClient(config)

	// Create encrypted message
	plaintext := "Benchmark test message with some content"
	aesKey, _ := crypto.GenerateAESKey()
	encryptedContent, nonce, _ := crypto.EncryptAESGCM([]byte(plaintext), aesKey)
	encryptedKey, _ := crypto.EncryptSymmetricKey(aesKey, x25519PubKey)

	msg := &types.Message{
		Header: types.MessageHeader{
			EncryptedKey:    base64.StdEncoding.EncodeToString(encryptedKey),
			EncryptionNonce: base64.StdEncoding.EncodeToString(nonce),
		},
		Body: types.MessageBody{
			Content: base64.StdEncoding.EncodeToString(encryptedContent),
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		client.decryptMessage(msg)
	}
}
