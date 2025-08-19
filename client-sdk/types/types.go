package types

import (
	"encoding/json"
	"time"
)

type User struct {
	UserID          string    `json:"user_id"`
	Username        string    `json:"username"`
	PublicKey       string    `json:"public_key"`
	X25519PublicKey string    `json:"x25519_public_key,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
}

type MessageHeader struct {
	From            string    `json:"from"`
	To              string    `json:"to"`
	IsBroadcast     bool      `json:"is_broadcast,omitempty"`
	Timestamp       time.Time `json:"timestamp"`
	Signature       string    `json:"signature,omitempty"`
	EncryptedKey    string    `json:"encrypted_key,omitempty"`    // Base64 encoded encrypted AES key (presence indicates encryption)
	EncryptionNonce string    `json:"encryption_nonce,omitempty"` // Base64 encoded nonce for AES-GCM
}

type MessageBody struct {
	Content string `json:"content"`
}

type Message struct {
	ID     int           `json:"id,omitempty"`
	Header MessageHeader `json:"header"`
	Body   MessageBody   `json:"body"`
	Status string        `json:"status,omitempty"`
}

type RegistrationRequest struct {
	UserID          string `json:"user_id"`
	Username        string `json:"username"`
	PublicKey       string `json:"public_key"`
	X25519PublicKey string `json:"x25519_public_key,omitempty"` // Public key for encryption
}

type LoginRequest struct {
	UserID string `json:"user_id"`
}

type ChallengeResponse struct {
	Challenge string `json:"challenge"`
}

type LoginVerifyRequest struct {
	UserID    string `json:"user_id"`
	Signature string `json:"signature"`
}

type TokenResponse struct {
	Token string `json:"token"`
}

type UserStatusResponse struct {
	Online  []string `json:"online"`
	Offline []string `json:"offline"`
}

type UserExistsResponse struct {
	Exists bool `json:"exists"`
}

type MessageHandler interface {
	HandleMessage(msg *Message) error
}

type MessageHandlerFunc func(msg *Message) error

func (f MessageHandlerFunc) HandleMessage(msg *Message) error {
	return f(msg)
}

type ExtendedMessage interface {
	GetBaseMessage() *Message
	SetBaseMessage(*Message)
}

type BaseExtendedMessage struct {
	*Message
}

func (b *BaseExtendedMessage) GetBaseMessage() *Message {
	return b.Message
}

func (b *BaseExtendedMessage) SetBaseMessage(m *Message) {
	b.Message = m
}

func ParseMessage(data []byte) (*Message, error) {
	var msg Message
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, err
	}
	return &msg, nil
}

func (m *Message) Marshal() ([]byte, error) {
	return json.Marshal(m)
}

type ConnectionState int

const (
	StateDisconnected ConnectionState = iota
	StateConnecting
	StateConnected
	StateReconnecting
)

func (cs ConnectionState) String() string {
	switch cs {
	case StateDisconnected:
		return "disconnected"
	case StateConnecting:
		return "connecting"
	case StateConnected:
		return "connected"
	case StateReconnecting:
		return "reconnecting"
	default:
		return "unknown"
	}
}
