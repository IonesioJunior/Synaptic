package ws

import (
	"net/http"
	"testing"
)

// TestServerGetUpgrader tests the getUpgrader method
func TestServerGetUpgrader(t *testing.T) {
	tests := []struct {
		name           string
		allowedOrigins []string
		testOrigin     string
		shouldAllow    bool
	}{
		{
			name:           "No origins configured - allow all",
			allowedOrigins: []string{},
			testOrigin:     "https://example.com",
			shouldAllow:    true,
		},
		{
			name:           "Origin in allowed list",
			allowedOrigins: []string{"https://example.com", "https://app.example.com"},
			testOrigin:     "https://example.com",
			shouldAllow:    true,
		},
		{
			name:           "Origin not in allowed list",
			allowedOrigins: []string{"https://example.com"},
			testOrigin:     "https://evil.com",
			shouldAllow:    false,
		},
		{
			name:           "Empty origin with restrictions",
			allowedOrigins: []string{"https://example.com"},
			testOrigin:     "",
			shouldAllow:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := &Server{
				allowedOrigins: tt.allowedOrigins,
			}

			upgrader := server.getUpgrader()
			if upgrader.CheckOrigin == nil {
				t.Error("CheckOrigin function should not be nil")
				return
			}

			// Create a proper http.Request
			req := &http.Request{
				Header: http.Header{},
			}
			if tt.testOrigin != "" {
				req.Header.Set("Origin", tt.testOrigin)
			}

			result := upgrader.CheckOrigin(req)

			if result != tt.shouldAllow {
				t.Errorf("CheckOrigin(%s) = %v, want %v", tt.testOrigin, result, tt.shouldAllow)
			}
		})
	}
}

// TestRateLimiterMoreCases tests additional rate limiting scenarios
func TestRateLimiterMoreCases(t *testing.T) {
	rl := NewRateLimiter(10, 20)

	// Test removal of non-existent user
	t.Run("RemoveNonExistentUser", func(t *testing.T) {
		rl.RemoveUser("non-existent-user")
		// Should not panic or cause issues
	})

	// Test multiple users
	t.Run("MultipleUsers", func(t *testing.T) {
		users := []string{"user1", "user2", "user3"}

		for _, user := range users {
			if !rl.Allow(user) {
				t.Errorf("First request for %s should be allowed", user)
			}
		}

		// Each user should have their own bucket
		if len(rl.buckets) != 3 {
			t.Errorf("Expected 3 buckets, got %d", len(rl.buckets))
		}

		// Remove users
		for _, user := range users {
			rl.RemoveUser(user)
		}

		// All buckets should be removed
		if len(rl.buckets) != 0 {
			t.Errorf("Expected 0 buckets after removal, got %d", len(rl.buckets))
		}
	})

	// Test bucket cleanup
	t.Run("BucketCleanup", func(t *testing.T) {
		// Add a bucket
		rl.Allow("temp-user")

		// Check it exists
		rl.lockMap.RLock()
		_, exists := rl.buckets["temp-user"]
		rl.lockMap.RUnlock()

		if !exists {
			t.Error("Bucket should exist after Allow")
		}

		// Remove user
		rl.RemoveUser("temp-user")

		// Check it's removed
		rl.lockMap.RLock()
		_, exists = rl.buckets["temp-user"]
		rl.lockMap.RUnlock()

		if exists {
			t.Error("Bucket should be removed after RemoveUser")
		}
	})
}
