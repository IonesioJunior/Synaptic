package models

import (
	"encoding/json"
	"testing"
	"time"
)

func TestUser(t *testing.T) {
	user := User{
		UserID:    "test-user-123",
		Username:  "Test User",
		PublicKey: "public-key-data",
		CreatedAt: time.Now(),
	}

	// Test JSON marshaling
	data, err := json.Marshal(user)
	if err != nil {
		t.Errorf("Failed to marshal User: %v", err)
	}

	// Test JSON unmarshaling
	var unmarshaledUser User
	err = json.Unmarshal(data, &unmarshaledUser)
	if err != nil {
		t.Errorf("Failed to unmarshal User: %v", err)
	}

	// Verify fields
	if unmarshaledUser.UserID != user.UserID {
		t.Errorf("UserID mismatch: expected %s, got %s", user.UserID, unmarshaledUser.UserID)
	}

	if unmarshaledUser.Username != user.Username {
		t.Errorf("Username mismatch: expected %s, got %s", user.Username, unmarshaledUser.Username)
	}

	if unmarshaledUser.PublicKey != user.PublicKey {
		t.Errorf("PublicKey mismatch: expected %s, got %s", user.PublicKey, unmarshaledUser.PublicKey)
	}
}

func TestMessageType(t *testing.T) {
	tests := []struct {
		name         string
		messageType  MessageType
		expectedStr  string
	}{
		{
			name:        "Direct message type",
			messageType: MessageTypeDirect,
			expectedStr: "direct",
		},
		{
			name:        "Broadcast message type",
			messageType: MessageTypeBroadcast,
			expectedStr: "broadcast",
		},
		{
			name:        "Server message type",
			messageType: MessageTypeServer,
			expectedStr: "server",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.messageType) != tt.expectedStr {
				t.Errorf("MessageType string mismatch: expected %s, got %s", tt.expectedStr, string(tt.messageType))
			}

			// Test JSON marshaling
			data, err := json.Marshal(tt.messageType)
			if err != nil {
				t.Errorf("Failed to marshal MessageType: %v", err)
			}

			// Should be quoted string in JSON
			expectedJSON := `"` + tt.expectedStr + `"`
			if string(data) != expectedJSON {
				t.Errorf("JSON mismatch: expected %s, got %s", expectedJSON, string(data))
			}

			// Test JSON unmarshaling
			var unmarshaledType MessageType
			err = json.Unmarshal(data, &unmarshaledType)
			if err != nil {
				t.Errorf("Failed to unmarshal MessageType: %v", err)
			}

			if unmarshaledType != tt.messageType {
				t.Errorf("Unmarshaled MessageType mismatch: expected %s, got %s", tt.messageType, unmarshaledType)
			}
		})
	}
}

func TestMessageHeader(t *testing.T) {
	now := time.Now()
	header := MessageHeader{
		From:            "sender-123",
		To:              "recipient-456",
		MessageType:     MessageTypeDirect,
		IsBroadcast:     false,
		Timestamp:       now,
		Signature:       "signature-data",
		EncryptedKey:    "encrypted-key-data",
		EncryptionNonce: "nonce-data",
	}

	// Test JSON marshaling
	data, err := json.Marshal(header)
	if err != nil {
		t.Errorf("Failed to marshal MessageHeader: %v", err)
	}

	// Test JSON unmarshaling
	var unmarshaledHeader MessageHeader
	err = json.Unmarshal(data, &unmarshaledHeader)
	if err != nil {
		t.Errorf("Failed to unmarshal MessageHeader: %v", err)
	}

	// Verify fields
	if unmarshaledHeader.From != header.From {
		t.Errorf("From mismatch: expected %s, got %s", header.From, unmarshaledHeader.From)
	}

	if unmarshaledHeader.To != header.To {
		t.Errorf("To mismatch: expected %s, got %s", header.To, unmarshaledHeader.To)
	}

	if unmarshaledHeader.MessageType != header.MessageType {
		t.Errorf("MessageType mismatch: expected %s, got %s", header.MessageType, unmarshaledHeader.MessageType)
	}

	if unmarshaledHeader.IsBroadcast != header.IsBroadcast {
		t.Errorf("IsBroadcast mismatch: expected %t, got %t", header.IsBroadcast, unmarshaledHeader.IsBroadcast)
	}

	if unmarshaledHeader.Signature != header.Signature {
		t.Errorf("Signature mismatch: expected %s, got %s", header.Signature, unmarshaledHeader.Signature)
	}

	if unmarshaledHeader.EncryptedKey != header.EncryptedKey {
		t.Errorf("EncryptedKey mismatch: expected %s, got %s", header.EncryptedKey, unmarshaledHeader.EncryptedKey)
	}

	if unmarshaledHeader.EncryptionNonce != header.EncryptionNonce {
		t.Errorf("EncryptionNonce mismatch: expected %s, got %s", header.EncryptionNonce, unmarshaledHeader.EncryptionNonce)
	}
}

func TestMessageHeaderOmitEmpty(t *testing.T) {
	// Test that omitempty fields are omitted when empty
	header := MessageHeader{
		From:        "sender",
		To:          "recipient",
		MessageType: MessageTypeDirect,
		Timestamp:   time.Now(),
		// Leave optional fields empty
	}

	data, err := json.Marshal(header)
	if err != nil {
		t.Errorf("Failed to marshal MessageHeader: %v", err)
	}

	// Check that empty fields are not included
	jsonStr := string(data)
	if contains(jsonStr, "is_broadcast") {
		t.Error("Empty IsBroadcast should be omitted")
	}
	if contains(jsonStr, "signature") {
		t.Error("Empty Signature should be omitted")
	}
	if contains(jsonStr, "encrypted_key") {
		t.Error("Empty EncryptedKey should be omitted")
	}
	if contains(jsonStr, "encryption_nonce") {
		t.Error("Empty EncryptionNonce should be omitted")
	}
}

func TestMessageBody(t *testing.T) {
	body := MessageBody{
		Content: "This is a test message content",
	}

	// Test JSON marshaling
	data, err := json.Marshal(body)
	if err != nil {
		t.Errorf("Failed to marshal MessageBody: %v", err)
	}

	// Test JSON unmarshaling
	var unmarshaledBody MessageBody
	err = json.Unmarshal(data, &unmarshaledBody)
	if err != nil {
		t.Errorf("Failed to unmarshal MessageBody: %v", err)
	}

	if unmarshaledBody.Content != body.Content {
		t.Errorf("Content mismatch: expected %s, got %s", body.Content, unmarshaledBody.Content)
	}
}

func TestMessage(t *testing.T) {
	now := time.Now()
	message := Message{
		ID: 123,
		Header: MessageHeader{
			From:        "sender",
			To:          "recipient",
			MessageType: MessageTypeDirect,
			Timestamp:   now,
		},
		Body: MessageBody{
			Content: "Test message content",
		},
		Status: "delivered",
	}

	// Test JSON marshaling
	data, err := json.Marshal(message)
	if err != nil {
		t.Errorf("Failed to marshal Message: %v", err)
	}

	// Test JSON unmarshaling
	var unmarshaledMessage Message
	err = json.Unmarshal(data, &unmarshaledMessage)
	if err != nil {
		t.Errorf("Failed to unmarshal Message: %v", err)
	}

	// Verify fields
	if unmarshaledMessage.ID != message.ID {
		t.Errorf("ID mismatch: expected %d, got %d", message.ID, unmarshaledMessage.ID)
	}

	if unmarshaledMessage.Header.From != message.Header.From {
		t.Errorf("Header.From mismatch: expected %s, got %s", message.Header.From, unmarshaledMessage.Header.From)
	}

	if unmarshaledMessage.Body.Content != message.Body.Content {
		t.Errorf("Body.Content mismatch: expected %s, got %s", message.Body.Content, unmarshaledMessage.Body.Content)
	}

	if unmarshaledMessage.Status != message.Status {
		t.Errorf("Status mismatch: expected %s, got %s", message.Status, unmarshaledMessage.Status)
	}
}

func TestMessageOmitEmpty(t *testing.T) {
	// Test that omitempty fields are omitted
	message := Message{
		Header: MessageHeader{
			From:        "sender",
			To:          "recipient",
			MessageType: MessageTypeDirect,
			Timestamp:   time.Now(),
		},
		Body: MessageBody{
			Content: "Test content",
		},
		// Leave ID and Status empty
	}

	data, err := json.Marshal(message)
	if err != nil {
		t.Errorf("Failed to marshal Message: %v", err)
	}

	jsonStr := string(data)
	if contains(jsonStr, `"id":0`) || contains(jsonStr, `"id":`) {
		t.Error("Zero ID should be omitted with omitempty")
	}
	if contains(jsonStr, `"status":""`) || (contains(jsonStr, `"status":`) && !contains(jsonStr, `"status":"delivered"`)) {
		t.Error("Empty Status should be omitted with omitempty")
	}
}

func TestServerCommand(t *testing.T) {
	params := json.RawMessage(`{"param1": "value1", "param2": 42}`)
	command := ServerCommand{
		Command:   "ping",
		Params:    params,
		RequestID: "req-123",
	}

	// Test JSON marshaling
	data, err := json.Marshal(command)
	if err != nil {
		t.Errorf("Failed to marshal ServerCommand: %v", err)
	}

	// Test JSON unmarshaling
	var unmarshaledCommand ServerCommand
	err = json.Unmarshal(data, &unmarshaledCommand)
	if err != nil {
		t.Errorf("Failed to unmarshal ServerCommand: %v", err)
	}

	// Verify fields
	if unmarshaledCommand.Command != command.Command {
		t.Errorf("Command mismatch: expected %s, got %s", command.Command, unmarshaledCommand.Command)
	}

	if unmarshaledCommand.RequestID != command.RequestID {
		t.Errorf("RequestID mismatch: expected %s, got %s", command.RequestID, unmarshaledCommand.RequestID)
	}

	// Verify params (RawMessage content should be equivalent, but formatting may differ)
	// Parse both to compare content rather than exact JSON formatting
	var originalParams, unmarshaledParams map[string]interface{}
	json.Unmarshal(command.Params, &originalParams)
	json.Unmarshal(unmarshaledCommand.Params, &unmarshaledParams)
	
	if originalParams["param1"] != unmarshaledParams["param1"] {
		t.Errorf("Param1 mismatch: expected %v, got %v", originalParams["param1"], unmarshaledParams["param1"])
	}
	if originalParams["param2"] != unmarshaledParams["param2"] {
		t.Errorf("Param2 mismatch: expected %v, got %v", originalParams["param2"], unmarshaledParams["param2"])
	}
}

func TestServerCommandOmitEmpty(t *testing.T) {
	command := ServerCommand{
		Command: "ping",
		// Leave Params and RequestID empty
	}

	data, err := json.Marshal(command)
	if err != nil {
		t.Errorf("Failed to marshal ServerCommand: %v", err)
	}

	jsonStr := string(data)
	if contains(jsonStr, "params") {
		t.Error("Empty Params should be omitted")
	}
	if contains(jsonStr, "request_id") {
		t.Error("Empty RequestID should be omitted")
	}
}

func TestServerResponse(t *testing.T) {
	response := ServerResponse{
		Success:   true,
		RequestID: "req-123",
		Result:    map[string]interface{}{"message": "pong"},
		Error:     "",
	}

	// Test JSON marshaling
	data, err := json.Marshal(response)
	if err != nil {
		t.Errorf("Failed to marshal ServerResponse: %v", err)
	}

	// Test JSON unmarshaling
	var unmarshaledResponse ServerResponse
	err = json.Unmarshal(data, &unmarshaledResponse)
	if err != nil {
		t.Errorf("Failed to unmarshal ServerResponse: %v", err)
	}

	// Verify fields
	if unmarshaledResponse.Success != response.Success {
		t.Errorf("Success mismatch: expected %t, got %t", response.Success, unmarshaledResponse.Success)
	}

	if unmarshaledResponse.RequestID != response.RequestID {
		t.Errorf("RequestID mismatch: expected %s, got %s", response.RequestID, unmarshaledResponse.RequestID)
	}

	// Result is interface{}, verify it's a map
	resultMap, ok := unmarshaledResponse.Result.(map[string]interface{})
	if !ok {
		t.Error("Result should be a map")
	} else {
		if resultMap["message"] != "pong" {
			t.Errorf("Result message mismatch: expected pong, got %v", resultMap["message"])
		}
	}
}

func TestServerResponseOmitEmpty(t *testing.T) {
	response := ServerResponse{
		Success: false,
		Error:   "Something went wrong",
		// Leave RequestID and Result empty
	}

	data, err := json.Marshal(response)
	if err != nil {
		t.Errorf("Failed to marshal ServerResponse: %v", err)
	}

	jsonStr := string(data)
	if contains(jsonStr, "request_id") && !contains(jsonStr, `"request_id":"`) {
		t.Error("Empty RequestID should be omitted")
	}
	if contains(jsonStr, "result") && !contains(jsonStr, `"result":`) {
		t.Error("Empty Result should be omitted")
	}
}

func TestComplexMessageFlow(t *testing.T) {
	// Test a complete message flow with all components
	now := time.Now()

	// Create a complex message with all fields
	message := Message{
		ID: 456,
		Header: MessageHeader{
			From:            "user123",
			To:              "user456", 
			MessageType:     MessageTypeServer,
			IsBroadcast:     false,
			Timestamp:       now,
			Signature:       "base64-signature",
			EncryptedKey:    "base64-encrypted-key",
			EncryptionNonce: "base64-nonce",
		},
		Body: MessageBody{
			Content: `{"command":"ping","params":{"test":true},"request_id":"req-789"}`,
		},
		Status: "pending",
	}

	// Marshal to JSON
	data, err := json.Marshal(message)
	if err != nil {
		t.Errorf("Failed to marshal complex message: %v", err)
	}

	// Unmarshal from JSON
	var unmarshaledMessage Message
	err = json.Unmarshal(data, &unmarshaledMessage)
	if err != nil {
		t.Errorf("Failed to unmarshal complex message: %v", err)
	}

	// Parse the server command from the body content
	var serverCommand ServerCommand
	err = json.Unmarshal([]byte(unmarshaledMessage.Body.Content), &serverCommand)
	if err != nil {
		t.Errorf("Failed to parse server command from message body: %v", err)
	}

	// Verify server command fields
	if serverCommand.Command != "ping" {
		t.Errorf("Server command mismatch: expected ping, got %s", serverCommand.Command)
	}

	if serverCommand.RequestID != "req-789" {
		t.Errorf("Server command RequestID mismatch: expected req-789, got %s", serverCommand.RequestID)
	}

	// Parse params
	var params map[string]interface{}
	err = json.Unmarshal(serverCommand.Params, &params)
	if err != nil {
		t.Errorf("Failed to parse server command params: %v", err)
	}

	if params["test"] != true {
		t.Errorf("Server command param mismatch: expected true, got %v", params["test"])
	}
}

func TestMessageValidation(t *testing.T) {
	tests := []struct {
		name        string
		messageType MessageType
		to          string
		isBroadcast bool
		valid       bool
		description string
	}{
		{
			name:        "Valid direct message",
			messageType: MessageTypeDirect,
			to:          "user123",
			isBroadcast: false,
			valid:       true,
			description: "Direct message with specific recipient",
		},
		{
			name:        "Valid broadcast message",
			messageType: MessageTypeBroadcast,
			to:          "broadcast",
			isBroadcast: true,
			valid:       true,
			description: "Broadcast message to all users",
		},
		{
			name:        "Valid server message",
			messageType: MessageTypeServer,
			to:          "server",
			isBroadcast: false,
			valid:       true,
			description: "Server command message",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			message := Message{
				Header: MessageHeader{
					From:        "sender",
					To:          tt.to,
					MessageType: tt.messageType,
					IsBroadcast: tt.isBroadcast,
					Timestamp:   time.Now(),
				},
				Body: MessageBody{
					Content: "Test content",
				},
			}

			// Test that the message can be marshaled and unmarshaled
			data, err := json.Marshal(message)
			if err != nil {
				if tt.valid {
					t.Errorf("Should be able to marshal valid message: %v", err)
				}
				return
			}

			var unmarshaledMessage Message
			err = json.Unmarshal(data, &unmarshaledMessage)
			if err != nil {
				if tt.valid {
					t.Errorf("Should be able to unmarshal valid message: %v", err)
				}
				return
			}

			// Verify the message type consistency
			if unmarshaledMessage.Header.MessageType != tt.messageType {
				t.Errorf("MessageType mismatch after marshal/unmarshal: expected %s, got %s", 
					tt.messageType, unmarshaledMessage.Header.MessageType)
			}
		})
	}
}

// Helper function to check if string contains substring
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
func BenchmarkMessageMarshal(b *testing.B) {
	message := Message{
		ID: 123,
		Header: MessageHeader{
			From:        "sender",
			To:          "recipient",
			MessageType: MessageTypeDirect,
			Timestamp:   time.Now(),
			Signature:   "signature-data",
		},
		Body: MessageBody{
			Content: "Benchmark message content",
		},
		Status: "delivered",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := json.Marshal(message)
		if err != nil {
			b.Fatalf("Marshal failed: %v", err)
		}
	}
}

func BenchmarkMessageUnmarshal(b *testing.B) {
	message := Message{
		ID: 123,
		Header: MessageHeader{
			From:        "sender",
			To:          "recipient",
			MessageType: MessageTypeDirect,
			Timestamp:   time.Now(),
			Signature:   "signature-data",
		},
		Body: MessageBody{
			Content: "Benchmark message content",
		},
		Status: "delivered",
	}

	data, _ := json.Marshal(message)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var unmarshaledMessage Message
		err := json.Unmarshal(data, &unmarshaledMessage)
		if err != nil {
			b.Fatalf("Unmarshal failed: %v", err)
		}
	}
}

func BenchmarkServerCommandMarshal(b *testing.B) {
	params := json.RawMessage(`{"param1": "value1", "param2": 42}`)
	command := ServerCommand{
		Command:   "ping",
		Params:    params,
		RequestID: "req-123",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := json.Marshal(command)
		if err != nil {
			b.Fatalf("Marshal failed: %v", err)
		}
	}
}