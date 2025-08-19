package ws

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"time"
	"websocketserver/models"
)

// processServerMessage handles incoming server messages
func (s *Server) processServerMessage(client *Client, msg models.Message) {
	// Create context with timeout for handler execution
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Verify signature is present
	if msg.Header.Signature == "" {
		s.sendServerError(client, msg, "Server messages must be signed", "")
		log.Printf("Server message from %s rejected: missing signature", client.userID)
		return
	}

	// Parse the command from message body
	var cmd models.ServerCommand
	if err := json.Unmarshal([]byte(msg.Body.Content), &cmd); err != nil {
		s.sendServerError(client, msg, "Invalid server command format", "")
		log.Printf("Server message from %s rejected: invalid command format: %v", client.userID, err)
		return
	}

	// Verify the signature
	if err := s.verifyServerMessageSignature(client.userID, msg); err != nil {
		s.sendServerError(client, msg, "Invalid signature", cmd.RequestID)
		log.Printf("Server message from %s rejected: signature verification failed: %v", client.userID, err)
		return
	}

	// Log successful signature verification
	log.Printf("Server message from %s verified: command=%s", client.userID, cmd.Command)

	// Look up the handler for this command
	handler, exists := s.serverHandlers.Get(cmd.Command)
	if !exists {
		s.sendServerError(client, msg, fmt.Sprintf("Unknown command: %s", cmd.Command), cmd.RequestID)
		log.Printf("Server message from %s rejected: unknown command '%s'", client.userID, cmd.Command)
		return
	}

	// Execute the handler in a goroutine with panic recovery
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("Handler panic for command '%s' from %s: %v", cmd.Command, client.userID, r)
				s.sendServerError(client, msg, "Internal server error", cmd.RequestID)
			}
		}()

		// Execute the handler
		result, err := handler.Handle(ctx, s, client.userID, cmd.Params)
		
		// Send response
		if err != nil {
			s.sendServerError(client, msg, err.Error(), cmd.RequestID)
			log.Printf("Handler error for command '%s' from %s: %v", cmd.Command, client.userID, err)
		} else {
			s.sendServerResponse(client, msg, result, cmd.RequestID)
			log.Printf("Handler success for command '%s' from %s", cmd.Command, client.userID)
		}
	}()
}

// verifyServerMessageSignature verifies the signature of a server message
func (s *Server) verifyServerMessageSignature(userID string, msg models.Message) error {
	// Get user's public key from database
	var publicKeyStr string
	query := "SELECT public_key FROM users WHERE user_id = ?"
	err := s.db.QueryRow(query, userID).Scan(&publicKeyStr)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("user not found: %s", userID)
		}
		return fmt.Errorf("database error: %w", err)
	}

	// Decode the public key
	publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKeyStr)
	if err != nil {
		return fmt.Errorf("invalid public key encoding: %w", err)
	}

	// Decode the signature
	signatureBytes, err := base64.StdEncoding.DecodeString(msg.Header.Signature)
	if err != nil {
		return fmt.Errorf("invalid signature encoding: %w", err)
	}

	// The signed data is the message body content
	signedData := []byte(msg.Body.Content)

	// Verify the signature
	if !ed25519.Verify(publicKeyBytes, signedData, signatureBytes) {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}

// sendServerResponse sends a successful response to a server message
func (s *Server) sendServerResponse(client *Client, originalMsg models.Message, result interface{}, requestID string) {
	response := models.ServerResponse{
		Success:   true,
		RequestID: requestID,
		Result:    result,
	}

	responseJSON, err := json.Marshal(response)
	if err != nil {
		log.Printf("Failed to marshal server response: %v", err)
		return
	}

	// Create a response message
	responseMsg := models.Message{
		Header: models.MessageHeader{
			From:        "server",
			To:          client.userID,
			MessageType: models.MessageTypeDirect,
			Timestamp:   time.Now(),
		},
		Body: models.MessageBody{
			Content: string(responseJSON),
		},
		Status: "delivered",
	}

	// Send the response to the client
	if data, err := json.Marshal(responseMsg); err == nil {
		select {
		case client.send <- data:
			// Successfully sent
		default:
			log.Printf("Failed to send server response to %s: channel full", client.userID)
		}
	}
}

// sendServerError sends an error response to a server message
func (s *Server) sendServerError(client *Client, originalMsg models.Message, errorMsg string, requestID string) {
	response := models.ServerResponse{
		Success:   false,
		RequestID: requestID,
		Error:     errorMsg,
	}

	responseJSON, err := json.Marshal(response)
	if err != nil {
		log.Printf("Failed to marshal error response: %v", err)
		return
	}

	// Create an error response message
	errorResponseMsg := models.Message{
		Header: models.MessageHeader{
			From:        "server",
			To:          client.userID,
			MessageType: models.MessageTypeDirect,
			Timestamp:   time.Now(),
		},
		Body: models.MessageBody{
			Content: string(responseJSON),
		},
		Status: "error",
	}

	// Send the error response to the client
	if data, err := json.Marshal(errorResponseMsg); err == nil {
		select {
		case client.send <- data:
			// Successfully sent
		default:
			log.Printf("Failed to send error response to %s: channel full", client.userID)
		}
	}
}

// RegisterServerHandler allows external code to register custom server message handlers
func (s *Server) RegisterServerHandler(command string, handler ServerMessageHandler) error {
	return s.serverHandlers.Register(command, handler)
}