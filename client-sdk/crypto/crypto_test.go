package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func TestGenerateAESKey(t *testing.T) {
	key, err := GenerateAESKey()
	if err != nil {
		t.Fatalf("GenerateAESKey failed: %v", err)
	}

	if len(key) != 32 {
		t.Errorf("Expected key length 32, got %d", len(key))
	}

	// Ensure keys are random
	key2, _ := GenerateAESKey()
	if bytes.Equal(key, key2) {
		t.Error("Generated keys should be different")
	}
}

func TestAESGCMEncryptionDecryption(t *testing.T) {
	tests := []struct {
		name      string
		plaintext string
	}{
		{"empty", ""},
		{"short", "Hello"},
		{"medium", "This is a medium length message for testing"},
		{"long", "This is a much longer message that contains multiple sentences. It should test the encryption and decryption of larger payloads. The encryption should handle this without any issues."},
		{"unicode", "Hello 世界 🌍 مرحبا"},
		{"special", "!@#$%^&*()_+-=[]{}|;':\",./<>?"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GenerateAESKey()
			if err != nil {
				t.Fatalf("GenerateAESKey failed: %v", err)
			}

			// Encrypt
			ciphertext, nonce, err := EncryptAESGCM([]byte(tt.plaintext), key)
			if err != nil {
				t.Fatalf("EncryptAESGCM failed: %v", err)
			}

			if len(nonce) != 12 {
				t.Errorf("Expected nonce length 12, got %d", len(nonce))
			}

			// Decrypt
			decrypted, err := DecryptAESGCM(ciphertext, key, nonce)
			if err != nil {
				t.Fatalf("DecryptAESGCM failed: %v", err)
			}

			if string(decrypted) != tt.plaintext {
				t.Errorf("Decrypted text doesn't match: got %q, want %q", string(decrypted), tt.plaintext)
			}
		})
	}
}

func TestDecryptAESGCMErrors(t *testing.T) {
	key, _ := GenerateAESKey()
	plaintext := []byte("test message")
	ciphertext, nonce, _ := EncryptAESGCM(plaintext, key)

	tests := []struct {
		name       string
		ciphertext []byte
		key        []byte
		nonce      []byte
		wantErr    bool
	}{
		{"wrong key", ciphertext, bytes.Repeat([]byte{1}, 32), nonce, true},
		{"wrong nonce", ciphertext, key, bytes.Repeat([]byte{1}, 12), true},
		{"corrupted ciphertext", append(ciphertext, byte(0)), key, nonce, true},
		{"empty ciphertext", []byte{}, key, nonce, true},
		{"invalid key size", ciphertext, []byte{1, 2, 3}, nonce, true},
		{"invalid nonce size", ciphertext, key, []byte{1, 2, 3}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecryptAESGCM(tt.ciphertext, tt.key, tt.nonce)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecryptAESGCM error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGenerateX25519KeyPair(t *testing.T) {
	pub, priv, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair failed: %v", err)
	}

	if len(pub) != 32 {
		t.Errorf("Expected public key length 32, got %d", len(pub))
	}

	if len(priv) != 32 {
		t.Errorf("Expected private key length 32, got %d", len(priv))
	}

	// Ensure keys are different
	if bytes.Equal(pub, priv) {
		t.Error("Public and private keys should be different")
	}

	// Generate another pair to ensure randomness
	pub2, priv2, _ := GenerateX25519KeyPair()
	if bytes.Equal(pub, pub2) || bytes.Equal(priv, priv2) {
		t.Error("Generated key pairs should be different")
	}
}

func TestDeriveX25519FromEd25519Seed(t *testing.T) {
	// Generate Ed25519 key
	_, ed25519Priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	// Derive X25519 keys
	x25519Pub, x25519Priv, err := DeriveX25519FromEd25519Seed(ed25519Priv)
	if err != nil {
		t.Fatalf("DeriveX25519FromEd25519Seed failed: %v", err)
	}

	if len(x25519Pub) != 32 {
		t.Errorf("Expected X25519 public key length 32, got %d", len(x25519Pub))
	}

	if len(x25519Priv) != 32 {
		t.Errorf("Expected X25519 private key length 32, got %d", len(x25519Priv))
	}

	// Derive again with same seed should produce same keys
	x25519Pub2, x25519Priv2, err := DeriveX25519FromEd25519Seed(ed25519Priv)
	if err != nil {
		t.Fatalf("Second derivation failed: %v", err)
	}

	if !bytes.Equal(x25519Pub, x25519Pub2) {
		t.Error("Same Ed25519 seed should produce same X25519 public key")
	}

	if !bytes.Equal(x25519Priv, x25519Priv2) {
		t.Error("Same Ed25519 seed should produce same X25519 private key")
	}
}

func TestDeriveX25519FromEd25519SeedInvalidInput(t *testing.T) {
	tests := []struct {
		name    string
		privKey ed25519.PrivateKey
	}{
		{"nil key", nil},
		{"empty key", ed25519.PrivateKey{}},
		{"short key", ed25519.PrivateKey([]byte{1, 2, 3})},
		{"wrong size", ed25519.PrivateKey(bytes.Repeat([]byte{1}, 31))},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := DeriveX25519FromEd25519Seed(tt.privKey)
			if err == nil {
				t.Error("Expected error for invalid input")
			}
		})
	}
}

func TestEncryptDecryptSymmetricKey(t *testing.T) {
	// Generate recipient's X25519 key pair
	recipientPub, recipientPriv, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate recipient keys: %v", err)
	}

	// Generate AES key to encrypt
	aesKey, err := GenerateAESKey()
	if err != nil {
		t.Fatalf("Failed to generate AES key: %v", err)
	}

	// Encrypt the AES key with recipient's public key
	encryptedKey, err := EncryptSymmetricKey(aesKey, recipientPub)
	if err != nil {
		t.Fatalf("EncryptSymmetricKey failed: %v", err)
	}

	// Encrypted key should be different from original
	if bytes.Equal(encryptedKey, aesKey) {
		t.Error("Encrypted key should be different from original")
	}

	// Decrypt the AES key with recipient's private key
	decryptedKey, err := DecryptSymmetricKey(encryptedKey, recipientPriv)
	if err != nil {
		t.Fatalf("DecryptSymmetricKey failed: %v", err)
	}

	// Decrypted key should match original
	if !bytes.Equal(decryptedKey, aesKey) {
		t.Error("Decrypted key doesn't match original")
	}
}

func TestEncryptSymmetricKeyErrors(t *testing.T) {
	validPub, _, _ := GenerateX25519KeyPair()
	validKey, _ := GenerateAESKey()

	tests := []struct {
		name         string
		symmetricKey []byte
		publicKey    []byte
		wantErr      bool
	}{
		{"valid", validKey, validPub, false},
		{"nil symmetric key", nil, validPub, true},
		{"empty symmetric key", []byte{}, validPub, true},
		{"nil public key", validKey, nil, true},
		{"wrong public key size", validKey, []byte{1, 2, 3}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := EncryptSymmetricKey(tt.symmetricKey, tt.publicKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("EncryptSymmetricKey error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDecryptSymmetricKeyErrors(t *testing.T) {
	recipientPub, recipientPriv, _ := GenerateX25519KeyPair()
	aesKey, _ := GenerateAESKey()
	validEncrypted, _ := EncryptSymmetricKey(aesKey, recipientPub)

	tests := []struct {
		name         string
		encryptedKey []byte
		privateKey   []byte
		wantErr      bool
	}{
		{"valid", validEncrypted, recipientPriv, false},
		{"nil encrypted key", nil, recipientPriv, true},
		{"empty encrypted key", []byte{}, recipientPriv, true},
		{"corrupted encrypted key", append(validEncrypted, byte(0)), recipientPriv, true},
		{"nil private key", validEncrypted, nil, true},
		{"wrong private key size", validEncrypted, []byte{1, 2, 3}, true},
		{"wrong private key", validEncrypted, bytes.Repeat([]byte{1}, 32), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecryptSymmetricKey(tt.encryptedKey, tt.privateKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecryptSymmetricKey error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestBase64Encoding(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"single byte", []byte{1}},
		{"multiple bytes", []byte{1, 2, 3, 4, 5}},
		{"random", func() []byte { b := make([]byte, 32); rand.Read(b); return b }()},
		{"text", []byte("Hello, World!")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := EncodeBase64(tt.data)

			// Check it's valid base64
			decoded, err := DecodeBase64(encoded)
			if err != nil {
				t.Fatalf("Failed to decode base64: %v", err)
			}

			if !bytes.Equal(decoded, tt.data) {
				t.Errorf("Decoded data doesn't match: got %v, want %v", decoded, tt.data)
			}
		})
	}
}

func TestDecodeBase64Errors(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid", base64.StdEncoding.EncodeToString([]byte("test")), false},
		{"empty", "", false},
		{"invalid chars", "!!!invalid!!!", true},
		{"wrong padding", "YQ", true},
		{"special chars", "hello@world", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeBase64(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecodeBase64 error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestEndToEndEncryption(t *testing.T) {
	// Simulate full encryption flow

	// Alice generates keys
	alicePub, alicePriv, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate Alice's keys: %v", err)
	}

	// Bob generates keys
	bobPub, bobPriv, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate Bob's keys: %v", err)
	}

	// Alice wants to send a message to Bob
	message := "Secret message from Alice to Bob"

	// Alice generates AES key for the message
	aesKey, err := GenerateAESKey()
	if err != nil {
		t.Fatalf("Failed to generate AES key: %v", err)
	}

	// Alice encrypts the message with AES
	encryptedMessage, nonce, err := EncryptAESGCM([]byte(message), aesKey)
	if err != nil {
		t.Fatalf("Failed to encrypt message: %v", err)
	}

	// Alice encrypts the AES key with Bob's public key
	encryptedKey, err := EncryptSymmetricKey(aesKey, bobPub)
	if err != nil {
		t.Fatalf("Failed to encrypt AES key: %v", err)
	}

	// Bob receives the encrypted message and key
	// Bob decrypts the AES key with his private key
	decryptedKey, err := DecryptSymmetricKey(encryptedKey, bobPriv)
	if err != nil {
		t.Fatalf("Bob failed to decrypt AES key: %v", err)
	}

	// Bob decrypts the message with the AES key
	decryptedMessage, err := DecryptAESGCM(encryptedMessage, decryptedKey, nonce)
	if err != nil {
		t.Fatalf("Bob failed to decrypt message: %v", err)
	}

	if string(decryptedMessage) != message {
		t.Errorf("Decrypted message doesn't match: got %q, want %q", string(decryptedMessage), message)
	}

	// Test that Alice cannot decrypt Bob's received message with her own private key
	_, err = DecryptSymmetricKey(encryptedKey, alicePriv)
	if err == nil {
		t.Error("Alice should not be able to decrypt with her own private key")
	}

	_ = alicePub // Alice's public key would be used if Bob wants to reply
}

func BenchmarkAESEncryption(b *testing.B) {
	key, _ := GenerateAESKey()
	plaintext := bytes.Repeat([]byte("a"), 1024) // 1KB of data

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := EncryptAESGCM(plaintext, key)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAESDecryption(b *testing.B) {
	key, _ := GenerateAESKey()
	plaintext := bytes.Repeat([]byte("a"), 1024)
	ciphertext, nonce, _ := EncryptAESGCM(plaintext, key)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := DecryptAESGCM(ciphertext, key, nonce)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkX25519KeyGeneration(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _, err := GenerateX25519KeyPair()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSymmetricKeyEncryption(b *testing.B) {
	pubKey, _, _ := GenerateX25519KeyPair()
	symmetricKey, _ := GenerateAESKey()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := EncryptSymmetricKey(symmetricKey, pubKey)
		if err != nil {
			b.Fatal(err)
		}
	}
}
