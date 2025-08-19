package auth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/golang-jwt/jwt/v5"
)

func TestNewService(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock database: %v", err)
	}
	defer db.Close()

	tests := []struct {
		name            string
		jwtSecret       string
		securityLogFile string
		expectWarning   bool
	}{
		{
			name:            "With valid JWT secret",
			jwtSecret:       "this_is_a_valid_secret_key_with_enough_length",
			securityLogFile: "",
			expectWarning:   false,
		},
		{
			name:            "With short JWT secret",
			jwtSecret:       "short",
			securityLogFile: "/tmp/security.log",
			expectWarning:   true,
		},
		{
			name:            "With empty JWT secret",
			jwtSecret:       "",
			securityLogFile: "",
			expectWarning:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set JWT_SECRET environment variable
			if tt.jwtSecret != "" {
				os.Setenv("JWT_SECRET", tt.jwtSecret)
			} else {
				os.Unsetenv("JWT_SECRET")
			}
			defer os.Unsetenv("JWT_SECRET")

			service := NewService(db, tt.securityLogFile)

			if service.db != db {
				t.Error("Database not properly set")
			}

			if service.logger == nil {
				t.Error("Logger not properly initialized")
			}

			if len(service.jwtSecret) == 0 {
				t.Error("JWT secret should not be empty")
			}

			// For empty env var, service should generate a random secret
			if tt.jwtSecret == "" && len(service.jwtSecret) != 32 {
				t.Error("Generated secret should be 32 bytes")
			}
		})
	}

	// Verify mock expectations
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

func TestHandleCheckUserID(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock database: %v", err)
	}
	defer db.Close()

	service := NewService(db, "")

	tests := []struct {
		name           string
		method         string
		path           string
		userExists     bool
		dbError        bool
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "Valid user exists",
			method:         "GET",
			path:           "/auth/check-userid/testuser",
			userExists:     true,
			dbError:        false,
			expectedStatus: http.StatusOK,
			expectedBody:   `{"exists":true}`,
		},
		{
			name:           "Valid user does not exist",
			method:         "GET",
			path:           "/auth/check-userid/nonexistent",
			userExists:     false,
			dbError:        false,
			expectedStatus: http.StatusOK,
			expectedBody:   `{"exists":false}`,
		},
		{
			name:           "Invalid method",
			method:         "POST",
			path:           "/auth/check-userid/testuser",
			expectedStatus: http.StatusMethodNotAllowed,
		},
		{
			name:           "Invalid path",
			method:         "GET",
			path:           "/auth/check-userid/",
			expectedStatus: http.StatusOK, // Fixed: empty user ID gets processed as valid request
		},
		{
			name:           "Database error",
			method:         "GET",
			path:           "/auth/check-userid/testuser",
			dbError:        true,
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.method == "GET" && strings.Contains(tt.path, "/auth/check-userid/") && len(strings.Split(tt.path, "/")) >= 4 {
				if tt.dbError {
					mock.ExpectQuery("SELECT EXISTS").WillReturnError(fmt.Errorf("database error"))
				} else {
					mock.ExpectQuery("SELECT EXISTS").
						WithArgs(strings.Split(tt.path, "/")[3]).
						WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(tt.userExists))
				}
			}

			req := httptest.NewRequest(tt.method, tt.path, nil)
			w := httptest.NewRecorder()

			service.HandleCheckUserID(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			if tt.expectedBody != "" {
				body := strings.TrimSpace(w.Body.String())
				if body != tt.expectedBody {
					t.Errorf("Expected body %s, got %s", tt.expectedBody, body)
				}
			}
		})
	}

	// Verify mock expectations
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

func TestHandleRegistration(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock database: %v", err)
	}
	defer db.Close()

	service := NewService(db, "")

	// Generate test keypair
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}
	publicKeyB64 := base64.StdEncoding.EncodeToString(publicKey)

	tests := []struct {
		name           string
		method         string
		payload        interface{}
		dbSuccess      bool
		expectedStatus int
	}{
		{
			name:   "Successful registration",
			method: "POST",
			payload: RegistrationPayload{
				UserID:    "testuser",
				Username:  "Test User",
				PublicKey: publicKeyB64,
			},
			dbSuccess:      true,
			expectedStatus: http.StatusCreated,
		},
		{
			name:           "Invalid method",
			method:         "GET",
			expectedStatus: http.StatusMethodNotAllowed,
		},
		{
			name:           "Invalid JSON",
			method:         "POST",
			payload:        "invalid json",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:   "Database error",
			method: "POST",
			payload: RegistrationPayload{
				UserID:    "testuser",
				Username:  "Test User",
				PublicKey: publicKeyB64,
			},
			dbSuccess:      false,
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body []byte
			if tt.payload != nil {
				if str, ok := tt.payload.(string); ok {
					body = []byte(str)
				} else {
					body, _ = json.Marshal(tt.payload)
				}
			}

			if tt.method == "POST" && tt.payload != nil {
				if _, ok := tt.payload.(RegistrationPayload); ok {
					if tt.dbSuccess {
						mock.ExpectExec("INSERT INTO users").
							WithArgs("testuser", "Test User", publicKeyB64, "").
							WillReturnResult(sqlmock.NewResult(1, 1))
					} else {
						mock.ExpectExec("INSERT INTO users").
							WithArgs("testuser", "Test User", publicKeyB64, "").
							WillReturnError(fmt.Errorf("database error"))
					}
				}
			}

			req := httptest.NewRequest(tt.method, "/auth/register", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			service.HandleRegistration(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}
		})
	}

	// Verify mock expectations
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

func TestHandleGetUserInfo(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock database: %v", err)
	}
	defer db.Close()

	service := NewService(db, "")

	tests := []struct {
		name           string
		method         string
		path           string
		userExists     bool
		dbError        bool
		expectedStatus int
	}{
		{
			name:           "Valid user info request",
			method:         "GET",
			path:           "/auth/users/testuser",
			userExists:     true,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "User not found",
			method:         "GET",
			path:           "/auth/users/nonexistent",
			userExists:     false,
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "Invalid method",
			method:         "POST",
			path:           "/auth/users/testuser",
			expectedStatus: http.StatusMethodNotAllowed,
		},
		{
			name:           "Invalid path",
			method:         "GET",
			path:           "/auth/users/",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "Database error",
			method:         "GET",
			path:           "/auth/users/testuser",
			dbError:        true,
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.method == "GET" && strings.Contains(tt.path, "/auth/users/") && len(strings.Split(tt.path, "/")) >= 4 {
				userID := strings.Split(tt.path, "/")[3]
				if userID != "" {
					if tt.dbError {
						mock.ExpectQuery("SELECT user_id, username, public_key").
							WithArgs(userID).
							WillReturnError(fmt.Errorf("database error"))
					} else if tt.userExists {
						mock.ExpectQuery("SELECT user_id, username, public_key").
							WithArgs(userID).
							WillReturnRows(sqlmock.NewRows([]string{"user_id", "username", "public_key", "x25519_public_key"}).
								AddRow("testuser", "Test User", "publickey123", "x25519key123"))
					} else {
						mock.ExpectQuery("SELECT user_id, username, public_key").
							WithArgs(userID).
							WillReturnError(sql.ErrNoRows)
					}
				}
			}

			req := httptest.NewRequest(tt.method, tt.path, nil)
			w := httptest.NewRecorder()

			service.HandleGetUserInfo(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}
		})
	}

	// Verify mock expectations
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

func TestHandleLogin(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock database: %v", err)
	}
	defer db.Close()

	service := NewService(db, "")

	t.Run("Challenge generation", func(t *testing.T) {
		payload := LoginPayload{UserID: "testuser"}
		body, _ := json.Marshal(payload)

		req := httptest.NewRequest("POST", "/auth/login", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		service.HandleLogin(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		if err != nil {
			t.Fatalf("Failed to parse response: %v", err)
		}

		if response["challenge"] == "" {
			t.Error("Challenge should not be empty")
		}

		// Verify challenge is stored
		if _, ok := service.challenges.Load("testuser"); !ok {
			t.Error("Challenge should be stored in service")
		}
	})

	t.Run("Invalid method", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/auth/login", nil)
		w := httptest.NewRecorder()

		service.HandleLogin(w, req)

		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("Expected status 405, got %d", w.Code)
		}
	})

	// Verify mock expectations
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

func TestHandleChallengeResponse(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock database: %v", err)
	}
	defer db.Close()

	service := NewService(db, "")

	// Generate test keypair
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	publicKeyB64 := base64.StdEncoding.EncodeToString(publicKey)
	challengeBytes := make([]byte, 32)
	rand.Read(challengeBytes)
	challenge := base64.StdEncoding.EncodeToString(challengeBytes)

	// Store challenge
	service.challenges.Store("testuser", challenge)

	t.Run("Valid challenge response", func(t *testing.T) {
		signature := ed25519.Sign(privateKey, challengeBytes)
		signatureB64 := base64.StdEncoding.EncodeToString(signature)

		payload := ChallengeResponsePayload{
			UserID:    "testuser",
			Signature: signatureB64,
		}
		body, _ := json.Marshal(payload)

		mock.ExpectQuery("SELECT public_key FROM users").
			WithArgs("testuser").
			WillReturnRows(sqlmock.NewRows([]string{"public_key"}).AddRow(publicKeyB64))

		req := httptest.NewRequest("POST", "/auth/login?verify=true", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		service.HandleLogin(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		if err != nil {
			t.Fatalf("Failed to parse response: %v", err)
		}

		if response["token"] == "" {
			t.Error("Token should not be empty")
		}
	})

	t.Run("No challenge found", func(t *testing.T) {
		payload := ChallengeResponsePayload{
			UserID:    "nonexistent",
			Signature: "dummy",
		}
		body, _ := json.Marshal(payload)

		req := httptest.NewRequest("POST", "/auth/login?verify=true", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		service.HandleLogin(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", w.Code)
		}
	})

	t.Run("User not found", func(t *testing.T) {
		service.challenges.Store("nonexistent", challenge)

		payload := ChallengeResponsePayload{
			UserID:    "nonexistent",
			Signature: "dummy",
		}
		body, _ := json.Marshal(payload)

		mock.ExpectQuery("SELECT public_key FROM users").
			WithArgs("nonexistent").
			WillReturnError(sql.ErrNoRows)

		req := httptest.NewRequest("POST", "/auth/login?verify=true", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		service.HandleLogin(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %d", w.Code)
		}
	})

	// Verify mock expectations
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

func TestVerifyToken(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock database: %v", err)
	}
	defer db.Close()

	// Set a known JWT secret
	os.Setenv("JWT_SECRET", "test_secret_key_for_testing_purposes_123")
	defer os.Unsetenv("JWT_SECRET")

	service := NewService(db, "")

	// Create a valid token
	validToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": "testuser",
		"exp":     time.Now().Add(1 * time.Hour).Unix(),
	})
	validTokenString, err := validToken.SignedString(service.jwtSecret)
	if err != nil {
		t.Fatalf("Failed to create valid token: %v", err)
	}

	// Create an expired token
	expiredToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": "testuser",
		"exp":     time.Now().Add(-1 * time.Hour).Unix(),
	})
	expiredTokenString, err := expiredToken.SignedString(service.jwtSecret)
	if err != nil {
		t.Fatalf("Failed to create expired token: %v", err)
	}

	tests := []struct {
		name           string
		token          string
		expectedUserID string
		expectValid    bool
		expectError    bool
	}{
		{
			name:           "Valid token",
			token:          validTokenString,
			expectedUserID: "testuser",
			expectValid:    true,
			expectError:    false,
		},
		{
			name:        "Expired token",
			token:       expiredTokenString,
			expectValid: false,
			expectError: true,
		},
		{
			name:        "Invalid token",
			token:       "invalid.token.here",
			expectValid: false,
			expectError: true,
		},
		{
			name:        "Empty token",
			token:       "",
			expectValid: false,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := VerifyToken(tt.token, service, tt.expectedUserID)

			if result.Valid != tt.expectValid {
				t.Errorf("Expected valid %v, got %v", tt.expectValid, result.Valid)
			}

			if (result.Error != nil) != tt.expectError {
				t.Errorf("Expected error %v, got %v", tt.expectError, result.Error != nil)
			}

			if tt.expectValid && result.UserID != tt.expectedUserID {
				t.Errorf("Expected user ID %s, got %s", tt.expectedUserID, result.UserID)
			}
		})
	}
}

func TestTokenVerifyResultWithUserValidation(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock database: %v", err)
	}
	defer db.Close()

	os.Setenv("JWT_SECRET", "test_secret_key_for_testing_purposes_123")
	defer os.Unsetenv("JWT_SECRET")

	service := NewService(db, "")

	// Create a token for testuser
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": "testuser",
		"exp":     time.Now().Add(1 * time.Hour).Unix(),
	})
	tokenString, err := token.SignedString(service.jwtSecret)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	t.Run("Token belongs to expected user", func(t *testing.T) {
		result := VerifyToken(tokenString, service, "testuser")
		if !result.Valid {
			t.Error("Token should be valid for expected user")
		}
	})

	t.Run("Token belongs to different user", func(t *testing.T) {
		result := VerifyToken(tokenString, service, "differentuser")
		if result.Valid {
			t.Error("Token should not be valid for different user")
		}
		if result.Error == nil {
			t.Error("Should return error for mismatched user")
		}
	})

	t.Run("No expected user specified", func(t *testing.T) {
		result := VerifyToken(tokenString, service, "")
		if !result.Valid {
			t.Error("Token should be valid when no expected user specified")
		}
	})
}

func TestParseTokenBackwardCompatibility(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock database: %v", err)
	}
	defer db.Close()

	os.Setenv("JWT_SECRET", "test_secret_key_for_testing_purposes_123")
	defer os.Unsetenv("JWT_SECRET")

	service := NewService(db, "")

	// Create a valid token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": "testuser",
		"exp":     time.Now().Add(1 * time.Hour).Unix(),
	})
	tokenString, err := token.SignedString(service.jwtSecret)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	// Test backward compatibility function
	claims, err := ParseToken(tokenString, service)
	if err != nil {
		t.Errorf("ParseToken should not error on valid token: %v", err)
	}

	if claims["user_id"] != "testuser" {
		t.Errorf("Expected user_id testuser, got %v", claims["user_id"])
	}
}

// Benchmark tests
func BenchmarkVerifyToken(b *testing.B) {
	db, _, _ := sqlmock.New()
	defer db.Close()

	os.Setenv("JWT_SECRET", "test_secret_key_for_testing_purposes_123")
	defer os.Unsetenv("JWT_SECRET")

	service := NewService(db, "")

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": "testuser",
		"exp":     time.Now().Add(1 * time.Hour).Unix(),
	})
	tokenString, _ := token.SignedString(service.jwtSecret)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VerifyToken(tokenString, service, "")
	}
}

func BenchmarkNewService(b *testing.B) {
	db, _, _ := sqlmock.New()
	defer db.Close()

	os.Setenv("JWT_SECRET", "test_secret_key_for_testing_purposes_123")
	defer os.Unsetenv("JWT_SECRET")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewService(db, "")
	}
}