package models

import (
	"encoding/json"
	"time"
)

// User represents a registered user.
type User struct {
	UserID    string    `json:"user_id"`
	Username  string    `json:"username"`
	PublicKey string    `json:"public_key"`
	CreatedAt time.Time `json:"created_at"`
}

// MessageType represents the type of message
type MessageType string

const (
	MessageTypeDirect    MessageType = "direct"
	MessageTypeBroadcast MessageType = "broadcast"
	MessageTypeServer    MessageType = "server"
)

// MessageHeader contains metadata about the message
type MessageHeader struct {
	From            string      `json:"from"`
	To              string      `json:"to"`
	MessageType     MessageType `json:"message_type"`               // Required: "direct", "broadcast", or "server"
	IsBroadcast     bool        `json:"is_broadcast,omitempty"`     // Deprecated: use MessageType instead
	Timestamp       time.Time   `json:"timestamp"`
	Signature       string      `json:"signature,omitempty"`        // Base64-encoded signature, required for server messages
	EncryptedKey    string      `json:"encrypted_key,omitempty"`    // Base64 encoded encrypted AES key (for E2E encryption)
	EncryptionNonce string      `json:"encryption_nonce,omitempty"` // Base64 encoded nonce (for E2E encryption)
}

// MessageBody contains the actual message content
type MessageBody struct {
	Content string `json:"content"`
}

// Message represents a complete message with header and body
type Message struct {
	ID     int           `json:"id,omitempty"` // Internal database ID
	Header MessageHeader `json:"header"`
	Body   MessageBody   `json:"body"`
	Status string        `json:"status,omitempty"` // Internal status: "pending", "delivered", "verified", "error"
}

// ServerCommand represents a command sent to the server for processing
type ServerCommand struct {
	Command   string          `json:"command"`             // The command to execute
	Params    json.RawMessage `json:"params,omitempty"`    // Command-specific parameters
	RequestID string          `json:"request_id,omitempty"` // Optional ID for tracking responses
}

// ServerResponse represents the server's response to a ServerCommand
type ServerResponse struct {
	Success   bool        `json:"success"`
	RequestID string      `json:"request_id,omitempty"` // Original request ID for correlation
	Result    interface{} `json:"result,omitempty"`      // Result data if successful
	Error     string      `json:"error,omitempty"`       // Error message if failed
}
