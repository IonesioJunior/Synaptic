package auth

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

// SecurityEvent represents a security-related event for audit logging
type SecurityEvent struct {
	Timestamp time.Time
	Event     string
	UserID    string
	IP        string
	Success   bool
	Details   string
}

// Logger handles security event logging
type Logger struct {
	logFile *os.File
	mu      sync.Mutex
}

// NewLogger creates a new security logger
func NewLogger(logFilePath string) *Logger {
	logger := &Logger{}

	// If a log file path is provided, open it for appending
	if logFilePath != "" {
		file, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			log.Printf("Failed to open security log file %s: %v (will use stdout only)", logFilePath, err)
		} else {
			logger.logFile = file
			log.Printf("Security audit logging enabled to file: %s", logFilePath)
		}
	}

	return logger
}

// Close closes the log file if open
func (l *Logger) Close() {
	if l.logFile != nil {
		l.logFile.Close()
	}
}

// LogAuthEvent logs an authentication event
func (l *Logger) LogAuthEvent(event SecurityEvent) {
	timestamp := event.Timestamp.Format(time.RFC3339)
	statusStr := "FAILED"
	if event.Success {
		statusStr = "SUCCESS"
	}

	logMessage := fmt.Sprintf(
		"[%s] SECURITY EVENT: %s | User: %s | IP: %s | Status: %s | %s",
		timestamp,
		event.Event,
		event.UserID,
		event.IP,
		statusStr,
		event.Details,
	)

	// Always log to stdout
	log.Println(logMessage)

	// Also log to file if configured
	if l.logFile != nil {
		l.mu.Lock()
		defer l.mu.Unlock()

		// Write to file with newline
		if _, err := l.logFile.WriteString(logMessage + "\n"); err != nil {
			log.Printf("Failed to write to security log file: %v", err)
		}
		// Sync to ensure it's written to disk immediately (important for security logs)
		l.logFile.Sync()
	}
}

// GetClientIP extracts the client IP address from the request
// Properly handles reverse proxies by checking X-Forwarded-For header
func GetClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first (for proxied requests)
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		// The first IP in the list is the original client
		return forwarded
	}

	// If no X-Forwarded-For, use RemoteAddr
	return r.RemoteAddr
}

// Common security event type constants
const (
	EventLogin                = "LOGIN"
	EventTokenCreation        = "TOKEN_CREATION"
	EventTokenVerification    = "TOKEN_VERIFICATION"
	EventUnauthorizedAccess   = "UNAUTHORIZED_ACCESS"
	EventDirectMessageSending = "DIRECT_MESSAGE_SENDING"
	EventWebSocketConnection  = "WEBSOCKET_CONNECTION"
)

// SendAuthErrorResponse sends a standardized authentication error response
func SendAuthErrorResponse(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	fmt.Fprintf(w, `{"error":true,"message":"%s"}`, message)
}
