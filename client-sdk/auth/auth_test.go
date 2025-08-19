package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"
)

func TestNewAuthManager(t *testing.T) {
	am, err := NewAuthManager("http://localhost:8080", "test-user", "Test User")
	if err != nil {
		t.Fatalf("Failed to create auth manager: %v", err)
	}

	if am.userID != "test-user" {
		t.Errorf("Expected userID 'test-user', got '%s'", am.userID)
	}

	if am.username != "Test User" {
		t.Errorf("Expected username 'Test User', got '%s'", am.username)
	}

	if am.baseURL != "http://localhost:8080" {
		t.Errorf("Expected baseURL 'http://localhost:8080', got '%s'", am.baseURL)
	}

	if len(am.privateKey) != ed25519.PrivateKeySize {
		t.Errorf("Invalid private key size: %d", len(am.privateKey))
	}

	if len(am.publicKey) != ed25519.PublicKeySize {
		t.Errorf("Invalid public key size: %d", len(am.publicKey))
	}
}

func TestNewAuthManagerWithKeys(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}

	am, err := NewAuthManagerWithKeys("http://localhost:8080", "test-user", "Test User", priv)
	if err != nil {
		t.Fatalf("Failed to create auth manager with keys: %v", err)
	}

	if !equalKeys(am.privateKey, priv) {
		t.Error("Private key mismatch")
	}

	if !equalKeys(am.publicKey, pub) {
		t.Error("Public key mismatch")
	}

	invalidKey := make([]byte, 10)
	_, err = NewAuthManagerWithKeys("http://localhost:8080", "test-user", "Test User", invalidKey)
	if err == nil {
		t.Error("Expected error for invalid key size")
	}
}

func TestLoadPrivateKeyFromBase64(t *testing.T) {
	_, originalPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}

	encoded := base64.StdEncoding.EncodeToString(originalPriv)

	loaded, err := LoadPrivateKeyFromBase64(encoded)
	if err != nil {
		t.Fatalf("Failed to load private key: %v", err)
	}

	if !equalKeys(loaded, originalPriv) {
		t.Error("Loaded key doesn't match original")
	}

	_, err = LoadPrivateKeyFromBase64("invalid-base64")
	if err == nil {
		t.Error("Expected error for invalid base64")
	}

	shortKey := base64.StdEncoding.EncodeToString([]byte("too-short"))
	_, err = LoadPrivateKeyFromBase64(shortKey)
	if err == nil {
		t.Error("Expected error for invalid key size")
	}
}

func TestKeyEncodingDecoding(t *testing.T) {
	am, err := NewAuthManager("http://localhost:8080", "test-user", "Test User")
	if err != nil {
		t.Fatalf("Failed to create auth manager: %v", err)
	}

	pubKeyBase64 := am.GetPublicKeyBase64()
	privKeyBase64 := am.GetPrivateKeyBase64()

	decodedPub, err := base64.StdEncoding.DecodeString(pubKeyBase64)
	if err != nil {
		t.Fatalf("Failed to decode public key: %v", err)
	}

	if !equalKeys(decodedPub, am.publicKey) {
		t.Error("Decoded public key doesn't match original")
	}

	decodedPriv, err := base64.StdEncoding.DecodeString(privKeyBase64)
	if err != nil {
		t.Fatalf("Failed to decode private key: %v", err)
	}

	if !equalKeys(decodedPriv, am.privateKey) {
		t.Error("Decoded private key doesn't match original")
	}
}

func TestSignMessage(t *testing.T) {
	am, err := NewAuthManager("http://localhost:8080", "test-user", "Test User")
	if err != nil {
		t.Fatalf("Failed to create auth manager: %v", err)
	}

	message := []byte("Test message to sign")
	signature := am.SignMessage(message)

	if signature == "" {
		t.Error("Signature should not be empty")
	}

	sigBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		t.Fatalf("Failed to decode signature: %v", err)
	}

	if len(sigBytes) != ed25519.SignatureSize {
		t.Errorf("Invalid signature size: %d", len(sigBytes))
	}

	if !ed25519.Verify(am.publicKey, message, sigBytes) {
		t.Error("Signature verification failed")
	}
}

func TestVerifySignature(t *testing.T) {
	am, err := NewAuthManager("http://localhost:8080", "test-user", "Test User")
	if err != nil {
		t.Fatalf("Failed to create auth manager: %v", err)
	}

	message := []byte("Test message")
	signature := am.SignMessage(message)
	publicKeyBase64 := am.GetPublicKeyBase64()

	if !am.VerifySignature(publicKeyBase64, signature, message) {
		t.Error("Valid signature should verify successfully")
	}

	if am.VerifySignature(publicKeyBase64, signature, []byte("Different message")) {
		t.Error("Signature should not verify with different message")
	}

	if am.VerifySignature("invalid-base64", signature, message) {
		t.Error("Should fail with invalid public key")
	}

	if am.VerifySignature(publicKeyBase64, "invalid-signature", message) {
		t.Error("Should fail with invalid signature")
	}
}

func TestTokenManagement(t *testing.T) {
	am, err := NewAuthManager("http://localhost:8080", "test-user", "Test User")
	if err != nil {
		t.Fatalf("Failed to create auth manager: %v", err)
	}

	_, err = am.GetToken()
	if err == nil {
		t.Error("Should error when not authenticated")
	}

	if am.IsTokenValid() {
		t.Error("Token should not be valid when not authenticated")
	}

	am.token = "test-token"
	am.tokenExp = time.Now().Add(1 * time.Hour)

	token, err := am.GetToken()
	if err != nil {
		t.Errorf("Should not error when token is valid: %v", err)
	}

	if token != "test-token" {
		t.Errorf("Expected 'test-token', got '%s'", token)
	}

	if !am.IsTokenValid() {
		t.Error("Token should be valid")
	}

	am.tokenExp = time.Now().Add(-1 * time.Hour)
	if am.IsTokenValid() {
		t.Error("Expired token should not be valid")
	}
}

func TestGetUserID(t *testing.T) {
	am, err := NewAuthManager("http://localhost:8080", "test-user", "Test User")
	if err != nil {
		t.Fatalf("Failed to create auth manager: %v", err)
	}

	if am.GetUserID() != "test-user" {
		t.Errorf("Expected 'test-user', got '%s'", am.GetUserID())
	}
}

func TestParseJWTClaims(t *testing.T) {
	validToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoidGVzdC11c2VyIiwiZXhwIjoxNzM1Njg5NjAwfQ.test"

	claims, err := ParseJWTClaims(validToken)
	if err != nil {
		t.Fatalf("Failed to parse valid token: %v", err)
	}

	userID, ok := claims["user_id"].(string)
	if !ok || userID != "test-user" {
		t.Errorf("Expected user_id 'test-user', got '%v'", claims["user_id"])
	}

	_, err = ParseJWTClaims("invalid-token")
	if err == nil {
		t.Error("Should error on invalid token")
	}

	_, err = ParseJWTClaims("")
	if err == nil {
		t.Error("Should error on empty token")
	}
}

func BenchmarkSignMessage(b *testing.B) {
	am, err := NewAuthManager("http://localhost:8080", "test-user", "Test User")
	if err != nil {
		b.Fatalf("Failed to create auth manager: %v", err)
	}

	message := []byte("Benchmark message to sign")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = am.SignMessage(message)
	}
}

func BenchmarkVerifySignature(b *testing.B) {
	am, err := NewAuthManager("http://localhost:8080", "test-user", "Test User")
	if err != nil {
		b.Fatalf("Failed to create auth manager: %v", err)
	}

	message := []byte("Benchmark message")
	signature := am.SignMessage(message)
	publicKeyBase64 := am.GetPublicKeyBase64()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = am.VerifySignature(publicKeyBase64, signature, message)
	}
}

func equalKeys(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
