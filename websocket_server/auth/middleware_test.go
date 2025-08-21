package auth

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/mattn/go-sqlite3"
)

func TestNewAuthMiddleware(t *testing.T) {
	authService := &Service{
		jwtSecret: []byte("test-secret"),
	}

	middleware := NewAuthMiddleware(authService)
	if middleware == nil {
		t.Fatal("NewAuthMiddleware returned nil")
	}
	if middleware.authService != authService {
		t.Error("AuthService not set correctly")
	}
}

func TestRequireAuth(t *testing.T) {
	// Create a test database
	db, err := setupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test DB: %v", err)
	}
	defer db.Close()

	authService := &Service{
		jwtSecret: []byte("test-secret"),
		db:        db,
	}
	middleware := NewAuthMiddleware(authService)

	// Create a test handler
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("authenticated"))
	})

	// Wrap with RequireAuth
	protected := middleware.RequireAuth(testHandler)

	tests := []struct {
		name           string
		token          string
		expectedStatus int
	}{
		{
			name:           "No token",
			token:          "",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Invalid token",
			token:          "invalid-token",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Valid token",
			token:          createTestToken(t, "test-user", authService.jwtSecret),
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Expired token",
			token:          createExpiredToken(t, "test-user", authService.jwtSecret),
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/protected", nil)
			if tt.token != "" {
				req.Header.Set("Authorization", "Bearer "+tt.token)
			}

			rec := httptest.NewRecorder()
			protected.ServeHTTP(rec, req)

			if rec.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rec.Code)
			}
		})
	}
}

// Helper function to setup test database
func setupTestDB() (*sql.DB, error) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		return nil, err
	}

	// Create users table
	_, err = db.Exec(`
		CREATE TABLE users (
			user_id TEXT PRIMARY KEY,
			username TEXT NOT NULL,
			public_key TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		return nil, err
	}

	// Add test users
	users := []struct {
		userID    string
		username  string
		publicKey string
	}{
		{"test-user", "Test User", "test-public-key"},
		{"allowed-user", "Allowed User", "allowed-public-key"},
		{"wrong-user", "Wrong User", "wrong-public-key"},
	}

	for _, u := range users {
		_, err = db.Exec(`
			INSERT INTO users (user_id, username, public_key) 
			VALUES (?, ?, ?)
		`, u.userID, u.username, u.publicKey)
		if err != nil {
			return nil, err
		}
	}

	return db, nil
}

func TestRequireSpecificUser(t *testing.T) {
	// Create a test database
	db, err := setupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test DB: %v", err)
	}
	defer db.Close()

	authService := &Service{
		jwtSecret: []byte("test-secret"),
		db:        db,
	}
	middleware := NewAuthMiddleware(authService)

	// Create a test handler
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("authorized"))
	})

	// Wrap with RequireSpecificUser
	protected := middleware.RequireSpecificUser("allowed-user", testHandler)

	tests := []struct {
		name           string
		token          string
		expectedStatus int
	}{
		{
			name:           "No token",
			token:          "",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Wrong user",
			token:          createTestToken(t, "wrong-user", authService.jwtSecret),
			expectedStatus: http.StatusUnauthorized, // Returns 401 to avoid leaking information
		},
		{
			name:           "Correct user",
			token:          createTestToken(t, "allowed-user", authService.jwtSecret),
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/protected", nil)
			if tt.token != "" {
				req.Header.Set("Authorization", "Bearer "+tt.token)
			}

			rec := httptest.NewRecorder()
			protected.ServeHTTP(rec, req)

			if rec.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rec.Code)
			}
		})
	}
}

func TestGetAuthenticatedUserID(t *testing.T) {
	tests := []struct {
		name           string
		setupContext   func(*http.Request) *http.Request
		expectedUserID string
		expectedOK     bool
	}{
		{
			name: "User ID in context",
			setupContext: func(r *http.Request) *http.Request {
				ctx := context.WithValue(r.Context(), AuthenticatedUserID("user_id"), "test-user")
				return r.WithContext(ctx)
			},
			expectedUserID: "test-user",
			expectedOK:     true,
		},
		{
			name: "No user in context",
			setupContext: func(r *http.Request) *http.Request {
				return r
			},
			expectedUserID: "",
			expectedOK:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req = tt.setupContext(req)

			userID, ok := GetAuthenticatedUserID(req)

			if userID != tt.expectedUserID {
				t.Errorf("Expected userID %q, got %q", tt.expectedUserID, userID)
			}
			if ok != tt.expectedOK {
				t.Errorf("Expected ok=%v, got %v", tt.expectedOK, ok)
			}
		})
	}
}

// Helper function to create a valid test token
func createTestToken(t *testing.T, userID string, secret []byte) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(time.Hour).Unix(),
	})

	tokenString, err := token.SignedString(secret)
	if err != nil {
		t.Fatalf("Failed to create test token: %v", err)
	}
	return tokenString
}

// Helper function to create an expired test token
func createExpiredToken(t *testing.T, userID string, secret []byte) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(-time.Hour).Unix(), // Expired 1 hour ago
	})

	tokenString, err := token.SignedString(secret)
	if err != nil {
		t.Fatalf("Failed to create expired token: %v", err)
	}
	return tokenString
}
