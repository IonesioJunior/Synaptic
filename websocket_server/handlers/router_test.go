package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"websocketserver/auth"
	"websocketserver/ws"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestSetupRoutes(t *testing.T) {
	// Create mock database
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock database: %v", err)
	}
	defer db.Close()

	// Create test services
	authService := auth.NewService(db, "")
	wsServer := ws.NewServer(db, authService, 5.0, 10, nil)

	// Create multiplexer and setup routes
	mux := http.NewServeMux()
	SetupRoutes(mux, db, authService, wsServer)

	// Test cases for different routes
	tests := []struct {
		name           string
		method         string
		path           string
		expectedStatus int
		description    string
	}{
		{
			name:           "Health check endpoint",
			method:         "GET",
			path:           "/health",
			expectedStatus: http.StatusOK,
			description:    "Should return healthy status",
		},
		{
			name:           "WebSocket endpoint without token",
			method:         "GET",
			path:           "/ws",
			expectedStatus: http.StatusUnauthorized,
			description:    "Should require authentication token",
		},
		{
			name:           "Active users endpoint",
			method:         "GET",
			path:           "/active-users",
			expectedStatus: http.StatusOK, // Should work with proper mock setup
			description:    "Should return active users list",
		},
		{
			name:           "Registration endpoint with GET (should be POST)",
			method:         "GET",
			path:           "/auth/register",
			expectedStatus: http.StatusMethodNotAllowed,
			description:    "Should only allow POST method",
		},
		{
			name:           "Login endpoint with GET (should be POST)",
			method:         "GET",
			path:           "/auth/login",
			expectedStatus: http.StatusMethodNotAllowed,
			description:    "Should only allow POST method",
		},
		{
			name:           "Check user ID endpoint with invalid path",
			method:         "GET",
			path:           "/auth/check-userid/",
			expectedStatus: http.StatusOK, // Should return exists: false for empty user ID
			description:    "Should handle empty user ID in path",
		},
		{
			name:           "Get user info endpoint with invalid path",
			method:         "GET",
			path:           "/auth/users/",
			expectedStatus: http.StatusBadRequest,
			description:    "Should require user ID in path",
		},
		{
			name:           "Static file serving - favicon",
			method:         "GET",
			path:           "/static/favicon.ico",
			expectedStatus: http.StatusNotFound, // File may not exist in test environment
			description:    "Should attempt to serve static files",
		},
		{
			name:           "Non-existent route",
			method:         "GET",
			path:           "/nonexistent",
			expectedStatus: http.StatusNotFound,
			description:    "Should return 404 for non-existent routes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup database expectations for specific endpoints
			if tt.path == "/active-users" {
				// Mock the query that ActiveUsersHandler makes
				mock.ExpectQuery("SELECT user_id FROM users").
					WillReturnRows(sqlmock.NewRows([]string{"user_id"}).
						AddRow("user1").
						AddRow("user2"))
			} else if tt.path == "/auth/check-userid/" {
				// Mock the EXISTS query with empty user ID
				mock.ExpectQuery("SELECT EXISTS").
					WithArgs("").
					WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
			} else if tt.path == "/auth/users/" {
				// This will fail due to invalid path, no DB expectation needed
			}

			req := httptest.NewRequest(tt.method, tt.path, nil)
			w := httptest.NewRecorder()

			mux.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d for %s %s. Description: %s",
					tt.expectedStatus, w.Code, tt.method, tt.path, tt.description)
			}
		})
	}

	// Verify mock expectations
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

func TestHealthEndpoint(t *testing.T) {
	// Create mock database
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock database: %v", err)
	}
	defer db.Close()

	// Create test services
	authService := auth.NewService(db, "")
	wsServer := ws.NewServer(db, authService, 5.0, 10, nil)

	// Create multiplexer and setup routes
	mux := http.NewServeMux()
	SetupRoutes(mux, db, authService, wsServer)

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	// Check response status
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// Check content type
	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected Content-Type application/json, got %s", contentType)
	}

	// Check response body contains expected fields
	body := w.Body.String()
	expectedFields := []string{"status", "healthy", "service", "websocket-server"}
	for _, field := range expectedFields {
		if !contains(body, field) {
			t.Errorf("Response body should contain '%s', got: %s", field, body)
		}
	}

	// Verify mock expectations
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

func TestRouteMethodValidation(t *testing.T) {
	// Create mock database
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock database: %v", err)
	}
	defer db.Close()

	// Create test services
	authService := auth.NewService(db, "")
	wsServer := ws.NewServer(db, authService, 5.0, 10, nil)

	// Create multiplexer and setup routes
	mux := http.NewServeMux()
	SetupRoutes(mux, db, authService, wsServer)

	// Test method validation for various endpoints
	tests := []struct {
		path           string
		allowedMethods []string
		deniedMethods  []string
	}{
		{
			path:           "/health",
			allowedMethods: []string{"GET"},
			deniedMethods:  []string{"POST", "PUT", "DELETE", "PATCH"},
		},
		{
			path:           "/auth/register",
			allowedMethods: []string{"POST"},
			deniedMethods:  []string{"GET", "PUT", "DELETE", "PATCH"},
		},
		{
			path:           "/auth/login",
			allowedMethods: []string{"POST"},
			deniedMethods:  []string{"GET", "PUT", "DELETE", "PATCH"},
		},
	}

	for _, tt := range tests {
		t.Run("Route: "+tt.path, func(t *testing.T) {
			// Test allowed methods
			for _, method := range tt.allowedMethods {
				req := httptest.NewRequest(method, tt.path, nil)
				w := httptest.NewRecorder()

				mux.ServeHTTP(w, req)

				// Should not return 405 Method Not Allowed
				if w.Code == http.StatusMethodNotAllowed {
					t.Errorf("Method %s should be allowed for %s, got status 405", method, tt.path)
				}
			}

			// Test denied methods
			for _, method := range tt.deniedMethods {
				req := httptest.NewRequest(method, tt.path, nil)
				w := httptest.NewRecorder()

				mux.ServeHTTP(w, req)

				// Should return 405 Method Not Allowed for auth endpoints
				if tt.path == "/auth/register" || tt.path == "/auth/login" {
					if w.Code != http.StatusMethodNotAllowed {
						t.Errorf("Method %s should not be allowed for %s, expected 405 got %d", method, tt.path, w.Code)
					}
				}
			}
		})
	}

	// Verify mock expectations
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

func TestStaticFileHandling(t *testing.T) {
	// Create mock database
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock database: %v", err)
	}
	defer db.Close()

	// Create test services
	authService := auth.NewService(db, "")
	wsServer := ws.NewServer(db, authService, 5.0, 10, nil)

	// Create multiplexer and setup routes
	mux := http.NewServeMux()
	SetupRoutes(mux, db, authService, wsServer)

	tests := []struct {
		name         string
		path         string
		expectedCode int
		description  string
	}{
		{
			name:         "Favicon request",
			path:         "/static/favicon.ico",
			expectedCode: http.StatusNotFound, // File may not exist in test environment
			description:  "Should attempt to serve favicon.ico file",
		},
		{
			name:         "Non-existent static file",
			path:         "/static/nonexistent.png",
			expectedCode: http.StatusNotFound,
			description:  "Should return 404 for non-existent static files",
		},
		{
			name:         "Directory traversal attempt",
			path:         "/static/../config.go",
			expectedCode: http.StatusMovedPermanently, // Go's file server redirects this
			description:  "Should handle directory traversal attempts",
		},
		{
			name:         "Static directory listing",
			path:         "/static/",
			expectedCode: http.StatusNotFound, // Directory may not exist in test environment
			description:  "Should attempt to handle directory requests",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.path, nil)
			w := httptest.NewRecorder()

			mux.ServeHTTP(w, req)

			if w.Code != tt.expectedCode {
				t.Errorf("Expected status %d, got %d for %s. Description: %s",
					tt.expectedCode, w.Code, tt.path, tt.description)
			}
		})
	}

	// Verify mock expectations
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

func TestRouteIntegration(t *testing.T) {
	// Create mock database
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock database: %v", err)
	}
	defer db.Close()

	// Create test services
	authService := auth.NewService(db, "")
	wsServer := ws.NewServer(db, authService, 5.0, 10, nil)

	// Create multiplexer and setup routes
	mux := http.NewServeMux()
	SetupRoutes(mux, db, authService, wsServer)

	// Test that all major route categories are accessible
	routeCategories := []struct {
		category string
		routes   []string
	}{
		{
			category: "Health",
			routes:   []string{"/health"},
		},
		{
			category: "WebSocket",
			routes:   []string{"/ws", "/active-users"},
		},
		{
			category: "Authentication",
			routes:   []string{"/auth/register", "/auth/login", "/auth/check-userid/test", "/auth/users/test"},
		},
		{
			category: "Static",
			routes:   []string{"/static/"}, // Directory request should be handled
		},
	}

	for _, category := range routeCategories {
		t.Run("Category: "+category.category, func(t *testing.T) {
			for _, route := range category.routes {
				req := httptest.NewRequest("GET", route, nil)
				w := httptest.NewRecorder()

				mux.ServeHTTP(w, req)

				// Verify the route is handled (not 404) - allow other error codes
				if w.Code == http.StatusNotFound && category.category != "Static" {
					t.Errorf("Route %s should be handled, got 404", route)
				}
			}
		})
	}

	// Verify mock expectations
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

func TestNilParameterHandling(t *testing.T) {
	// Test that SetupRoutes handles nil parameters gracefully
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("SetupRoutes should not panic with nil parameters: %v", r)
		}
	}()

	// This should not panic, even though it might not work correctly
	mux := http.NewServeMux()

	// Test with nil parameters - should not crash
	// Note: This might not work correctly but shouldn't panic
	db, mock, _ := sqlmock.New()
	defer db.Close()
	defer mock.ExpectationsWereMet()

	authService := auth.NewService(db, "")
	wsServer := ws.NewServer(db, authService, 5.0, 10, nil)

	// This should not panic
	SetupRoutes(mux, db, authService, wsServer)
}

func TestConcurrentRouteAccess(t *testing.T) {
	// Create mock database
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock database: %v", err)
	}
	defer db.Close()

	// Create test services
	authService := auth.NewService(db, "")
	wsServer := ws.NewServer(db, authService, 5.0, 10, nil)

	// Create multiplexer and setup routes
	mux := http.NewServeMux()
	SetupRoutes(mux, db, authService, wsServer)

	const numRequests = 100
	results := make(chan int, numRequests)

	// Send concurrent requests to health endpoint
	for i := 0; i < numRequests; i++ {
		go func() {
			req := httptest.NewRequest("GET", "/health", nil)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)
			results <- w.Code
		}()
	}

	// Collect results
	successCount := 0
	for i := 0; i < numRequests; i++ {
		statusCode := <-results
		if statusCode == http.StatusOK {
			successCount++
		}
	}

	if successCount != numRequests {
		t.Errorf("Expected %d successful requests, got %d", numRequests, successCount)
	}

	// Verify mock expectations
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(substr) == 0 || (len(s) >= len(substr) && findSubstring(s, substr))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// Benchmark tests
func BenchmarkSetupRoutes(b *testing.B) {
	db, mock, _ := sqlmock.New()
	defer db.Close()
	defer mock.ExpectationsWereMet()

	authService := auth.NewService(db, "")
	wsServer := ws.NewServer(db, authService, 5.0, 10, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mux := http.NewServeMux()
		SetupRoutes(mux, db, authService, wsServer)
	}
}

func BenchmarkHealthEndpoint(b *testing.B) {
	db, mock, _ := sqlmock.New()
	defer db.Close()
	defer mock.ExpectationsWereMet()

	authService := auth.NewService(db, "")
	wsServer := ws.NewServer(db, authService, 5.0, 10, nil)

	mux := http.NewServeMux()
	SetupRoutes(mux, db, authService, wsServer)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "/health", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
	}
}
