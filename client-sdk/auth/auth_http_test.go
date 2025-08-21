package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/genericwsserver/client-sdk/types"
)

// Mock HTTP server for testing
func setupMockServer() *httptest.Server {
	mux := http.NewServeMux()

	// Mock user existence check
	mux.HandleFunc("/auth/check-userid/", func(w http.ResponseWriter, r *http.Request) {
		userID := r.URL.Path[len("/auth/check-userid/"):]
		exists := userID == "existing-user"

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(types.UserExistsResponse{
			Exists: exists,
		})
	})

	// Mock registration
	mux.HandleFunc("/auth/register", func(w http.ResponseWriter, r *http.Request) {
		var req types.RegistrationRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		if req.UserID == "duplicate-user" {
			http.Error(w, "User already exists", http.StatusConflict)
			return
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{
			"message": "User registered successfully",
		})
	})

	// Mock login challenge
	mux.HandleFunc("/auth/login", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("verify") == "true" {
			// Verification request
			var req types.LoginVerifyRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "Invalid request", http.StatusBadRequest)
				return
			}

			if req.UserID == "invalid-user" {
				http.Error(w, "Invalid credentials", http.StatusUnauthorized)
				return
			}

			// Generate mock JWT token
			token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
				"user_id": req.UserID,
				"exp":     time.Now().Add(24 * time.Hour).Unix(),
			})
			tokenString, _ := token.SignedString([]byte("test-secret"))

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(types.TokenResponse{
				Token: tokenString,
			})
		} else {
			// Challenge request
			var req types.LoginRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "Invalid request", http.StatusBadRequest)
				return
			}

			if req.UserID == "nonexistent-user" {
				http.Error(w, "User not found", http.StatusNotFound)
				return
			}

			// Generate mock challenge
			challenge := make([]byte, 32)
			rand.Read(challenge)
			challengeBase64 := base64.StdEncoding.EncodeToString(challenge)

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(types.ChallengeResponse{
				Challenge: challengeBase64,
			})
		}
	})

	// Mock get user info
	mux.HandleFunc("/auth/users/", func(w http.ResponseWriter, r *http.Request) {
		userID := r.URL.Path[len("/auth/users/"):]

		if userID == "nonexistent" {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}

		if userID == "error-user" {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Generate mock X25519 public key
		x25519Pub := make([]byte, 32)
		rand.Read(x25519Pub)

		user := types.User{
			UserID:          userID,
			Username:        fmt.Sprintf("User %s", userID),
			PublicKey:       base64.StdEncoding.EncodeToString(make([]byte, 32)),
			X25519PublicKey: base64.StdEncoding.EncodeToString(x25519Pub),
			CreatedAt:       time.Now(),
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(user)
	})

	return httptest.NewServer(mux)
}

func TestCheckUserExists(t *testing.T) {
	server := setupMockServer()
	defer server.Close()

	am, err := NewAuthManager(server.URL, "test-user", "Test User")
	if err != nil {
		t.Fatalf("Failed to create auth manager: %v", err)
	}

	tests := []struct {
		name     string
		userID   string
		expected bool
		wantErr  bool
	}{
		{"existing user", "existing-user", true, false},
		{"new user", "new-user", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			am.userID = tt.userID
			exists, err := am.CheckUserExists()

			if (err != nil) != tt.wantErr {
				t.Errorf("CheckUserExists() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if exists != tt.expected {
				t.Errorf("CheckUserExists() = %v, want %v", exists, tt.expected)
			}
		})
	}
}

func TestRegister(t *testing.T) {
	server := setupMockServer()
	defer server.Close()

	tests := []struct {
		name    string
		userID  string
		wantErr bool
	}{
		{"successful registration", "new-user", false},
		{"duplicate user", "duplicate-user", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			am, err := NewAuthManager(server.URL, tt.userID, "Test User")
			if err != nil {
				t.Fatalf("Failed to create auth manager: %v", err)
			}

			err = am.Register()
			if (err != nil) != tt.wantErr {
				t.Errorf("Register() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestLogin(t *testing.T) {
	server := setupMockServer()
	defer server.Close()

	tests := []struct {
		name    string
		userID  string
		wantErr bool
	}{
		{"successful login", "test-user", false},
		{"nonexistent user", "nonexistent-user", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			am, err := NewAuthManager(server.URL, tt.userID, "Test User")
			if err != nil {
				t.Fatalf("Failed to create auth manager: %v", err)
			}

			err = am.Login()
			if (err != nil) != tt.wantErr {
				t.Errorf("Login() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr {
				if am.token == "" {
					t.Error("Token should be set after successful login")
				}
				if !am.IsTokenValid() {
					t.Error("Token should be valid after successful login")
				}
			}
		})
	}
}

func TestRequestChallenge(t *testing.T) {
	server := setupMockServer()
	defer server.Close()

	am, err := NewAuthManager(server.URL, "test-user", "Test User")
	if err != nil {
		t.Fatalf("Failed to create auth manager: %v", err)
	}

	challenge, err := am.requestChallenge()
	if err != nil {
		t.Fatalf("requestChallenge() error = %v", err)
	}

	if challenge == "" {
		t.Error("Challenge should not be empty")
	}

	// Test with nonexistent user
	am.userID = "nonexistent-user"
	_, err = am.requestChallenge()
	if err == nil {
		t.Error("Expected error for nonexistent user")
	}
}

func TestVerifyChallenge(t *testing.T) {
	server := setupMockServer()
	defer server.Close()

	am, err := NewAuthManager(server.URL, "test-user", "Test User")
	if err != nil {
		t.Fatalf("Failed to create auth manager: %v", err)
	}

	// Create a valid challenge
	challenge := make([]byte, 32)
	rand.Read(challenge)
	challengeBase64 := base64.StdEncoding.EncodeToString(challenge)

	token, err := am.verifyChallenge(challengeBase64)
	if err != nil {
		t.Fatalf("verifyChallenge() error = %v", err)
	}

	if token == "" {
		t.Error("Token should not be empty")
	}

	// Test with invalid base64
	_, err = am.verifyChallenge("invalid-base64!")
	if err == nil {
		t.Error("Expected error for invalid base64 challenge")
	}

	// Test with invalid user
	am.userID = "invalid-user"
	_, err = am.verifyChallenge(challengeBase64)
	if err == nil {
		t.Error("Expected error for invalid user")
	}
}

func TestGetUserInfo(t *testing.T) {
	server := setupMockServer()
	defer server.Close()

	am, err := NewAuthManager(server.URL, "test-user", "Test User")
	if err != nil {
		t.Fatalf("Failed to create auth manager: %v", err)
	}

	tests := []struct {
		name    string
		userID  string
		wantErr bool
	}{
		{"existing user", "test-user", false},
		{"another user", "another-user", false},
		{"nonexistent user", "nonexistent", true},
		{"error user", "error-user", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, err := am.GetUserInfo(tt.userID)

			if (err != nil) != tt.wantErr {
				t.Errorf("GetUserInfo() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if user.UserID != tt.userID {
					t.Errorf("UserID = %v, want %v", user.UserID, tt.userID)
				}
				if user.PublicKey == "" {
					t.Error("PublicKey should not be empty")
				}
				if user.X25519PublicKey == "" {
					t.Error("X25519PublicKey should not be empty")
				}
			}
		})
	}
}

func TestSetInsecureTLS(t *testing.T) {
	am, err := NewAuthManager("https://localhost:8080", "test-user", "Test User")
	if err != nil {
		t.Fatalf("Failed to create auth manager: %v", err)
	}

	// Initially should be false
	if am.insecureTLS {
		t.Error("insecureTLS should be false by default")
	}

	// Set to true
	am.SetInsecureTLS(true)
	if !am.insecureTLS {
		t.Error("insecureTLS should be true after setting")
	}

	// Check that HTTP client is updated
	transport := am.httpClient.Transport.(*http.Transport)
	if !transport.TLSClientConfig.InsecureSkipVerify {
		t.Error("TLS config should have InsecureSkipVerify set to true")
	}

	// Set back to false
	am.SetInsecureTLS(false)
	if am.insecureTLS {
		t.Error("insecureTLS should be false after unsetting")
	}
}

func TestGetX25519PublicKeyBase64(t *testing.T) {
	am, err := NewAuthManager("http://localhost:8080", "test-user", "Test User")
	if err != nil {
		t.Fatalf("Failed to create auth manager: %v", err)
	}

	x25519PubBase64 := am.GetX25519PublicKeyBase64()
	if x25519PubBase64 == "" {
		t.Error("X25519 public key base64 should not be empty")
	}

	decoded, err := base64.StdEncoding.DecodeString(x25519PubBase64)
	if err != nil {
		t.Fatalf("Failed to decode X25519 public key: %v", err)
	}

	if len(decoded) != 32 {
		t.Errorf("X25519 public key should be 32 bytes, got %d", len(decoded))
	}
}

func TestGetUserPublicKeyX25519(t *testing.T) {
	server := setupMockServer()
	defer server.Close()

	am, err := NewAuthManager(server.URL, "test-user", "Test User")
	if err != nil {
		t.Fatalf("Failed to create auth manager: %v", err)
	}

	// Test getting own key
	ownKey, err := am.GetUserPublicKeyX25519("test-user")
	if err != nil {
		t.Fatalf("Failed to get own X25519 key: %v", err)
	}
	if len(ownKey) != 32 {
		t.Errorf("Own X25519 key should be 32 bytes, got %d", len(ownKey))
	}

	// Test getting another user's key
	otherKey, err := am.GetUserPublicKeyX25519("other-user")
	if err != nil {
		t.Fatalf("Failed to get other user's X25519 key: %v", err)
	}
	if len(otherKey) != 32 {
		t.Errorf("Other user's X25519 key should be 32 bytes, got %d", len(otherKey))
	}

	// Test caching - should return same key
	cachedKey, err := am.GetUserPublicKeyX25519("other-user")
	if err != nil {
		t.Fatalf("Failed to get cached X25519 key: %v", err)
	}
	if !equalKeys(otherKey, cachedKey) {
		t.Error("Cached key should match original")
	}

	// Test nonexistent user
	_, err = am.GetUserPublicKeyX25519("nonexistent")
	if err == nil {
		t.Error("Expected error for nonexistent user")
	}
}

func TestGetOwnX25519PrivateKey(t *testing.T) {
	am, err := NewAuthManager("http://localhost:8080", "test-user", "Test User")
	if err != nil {
		t.Fatalf("Failed to create auth manager: %v", err)
	}

	privKey, err := am.GetOwnX25519PrivateKey()
	if err != nil {
		t.Fatalf("Failed to get own X25519 private key: %v", err)
	}

	if len(privKey) != 32 {
		t.Errorf("X25519 private key should be 32 bytes, got %d", len(privKey))
	}

	// Test with nil key
	am.x25519PrivKey = nil
	_, err = am.GetOwnX25519PrivateKey()
	if err == nil {
		t.Error("Expected error when X25519 private key is nil")
	}
}

func TestClearKeyCache(t *testing.T) {
	server := setupMockServer()
	defer server.Close()

	am, err := NewAuthManager(server.URL, "test-user", "Test User")
	if err != nil {
		t.Fatalf("Failed to create auth manager: %v", err)
	}

	// Populate cache
	_, err = am.GetUserPublicKeyX25519("cached-user")
	if err != nil {
		t.Fatalf("Failed to cache user key: %v", err)
	}

	// Verify cache has entry
	am.keyCacheMu.RLock()
	cacheSize := len(am.keyCache)
	am.keyCacheMu.RUnlock()

	if cacheSize == 0 {
		t.Error("Cache should have at least one entry")
	}

	// Clear cache
	am.ClearKeyCache()

	// Verify cache is empty
	am.keyCacheMu.RLock()
	cacheSize = len(am.keyCache)
	am.keyCacheMu.RUnlock()

	if cacheSize != 0 {
		t.Errorf("Cache should be empty after clear, has %d entries", cacheSize)
	}
}

func TestTokenExpiration(t *testing.T) {
	server := setupMockServer()
	defer server.Close()

	am, err := NewAuthManager(server.URL, "test-user", "Test User")
	if err != nil {
		t.Fatalf("Failed to create auth manager: %v", err)
	}

	// Set expired token
	am.token = "expired-token"
	am.tokenExp = time.Now().Add(-1 * time.Hour)

	// GetToken should trigger re-login
	token, err := am.GetToken()
	if err != nil {
		t.Fatalf("GetToken with expired token failed: %v", err)
	}

	// Should have new token
	if token == "expired-token" {
		t.Error("Should have new token after expiration")
	}

	// Token should be valid now
	if !am.IsTokenValid() {
		t.Error("Token should be valid after re-login")
	}
}

func TestNewAuthManagerWithKeys_Ed25519Derivation(t *testing.T) {
	// Generate Ed25519 key pair
	_, ed25519Priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 keys: %v", err)
	}

	// Create auth manager with Ed25519 keys
	am, err := NewAuthManagerWithKeys("http://localhost:8080", "test-user", "Test User", ed25519Priv)
	if err != nil {
		t.Fatalf("Failed to create auth manager: %v", err)
	}

	// Verify X25519 keys were derived
	if len(am.x25519PrivKey) != 32 {
		t.Errorf("X25519 private key should be 32 bytes, got %d", len(am.x25519PrivKey))
	}

	if len(am.x25519PubKey) != 32 {
		t.Errorf("X25519 public key should be 32 bytes, got %d", len(am.x25519PubKey))
	}

	// Create another auth manager with same Ed25519 key
	am2, err := NewAuthManagerWithKeys("http://localhost:8080", "test-user", "Test User", ed25519Priv)
	if err != nil {
		t.Fatalf("Failed to create second auth manager: %v", err)
	}

	// X25519 keys should be deterministically derived and match
	if !equalKeys(am.x25519PrivKey, am2.x25519PrivKey) {
		t.Error("X25519 private keys should match when derived from same Ed25519 key")
	}

	if !equalKeys(am.x25519PubKey, am2.x25519PubKey) {
		t.Error("X25519 public keys should match when derived from same Ed25519 key")
	}
}
