package types

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func TestParseMessage(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	
	tests := []struct {
		name    string
		data    string
		want    *Message
		wantErr bool
	}{
		{
			name: "valid message",
			data: `{
				"id": 123,
				"header": {
					"from": "user1",
					"to": "user2",
					"timestamp": "` + now.Format(time.RFC3339) + `",
					"signature": "sig123"
				},
				"body": {
					"content": "Hello World"
				},
				"status": "sent"
			}`,
			want: &Message{
				ID: 123,
				Header: MessageHeader{
					From:      "user1",
					To:        "user2",
					Timestamp: now,
					Signature: "sig123",
				},
				Body: MessageBody{
					Content: "Hello World",
				},
				Status: "sent",
			},
			wantErr: false,
		},
		{
			name: "broadcast message",
			data: `{
				"header": {
					"from": "user1",
					"to": "broadcast",
					"is_broadcast": true,
					"timestamp": "` + now.Format(time.RFC3339) + `"
				},
				"body": {
					"content": "Broadcast message"
				}
			}`,
			want: &Message{
				Header: MessageHeader{
					From:        "user1",
					To:          "broadcast",
					IsBroadcast: true,
					Timestamp:   now,
				},
				Body: MessageBody{
					Content: "Broadcast message",
				},
			},
			wantErr: false,
		},
		{
			name: "encrypted message",
			data: `{
				"header": {
					"from": "user1",
					"to": "user2",
					"timestamp": "` + now.Format(time.RFC3339) + `",
					"encrypted_key": "encKey123",
					"encryption_nonce": "nonce456"
				},
				"body": {
					"content": "encryptedContent789"
				}
			}`,
			want: &Message{
				Header: MessageHeader{
					From:            "user1",
					To:              "user2",
					Timestamp:       now,
					EncryptedKey:    "encKey123",
					EncryptionNonce: "nonce456",
				},
				Body: MessageBody{
					Content: "encryptedContent789",
				},
			},
			wantErr: false,
		},
		{
			name:    "invalid json",
			data:    `{invalid json`,
			want:    nil,
			wantErr: true,
		},
		{
			name:    "empty data",
			data:    ``,
			want:    nil,
			wantErr: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseMessage([]byte(tt.data))
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseMessage() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseMessage() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestMessage_Marshal(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	
	msg := &Message{
		ID: 456,
		Header: MessageHeader{
			From:      "sender",
			To:        "receiver",
			Timestamp: now,
			Signature: "testsig",
		},
		Body: MessageBody{
			Content: "Test content",
		},
		Status: "delivered",
	}
	
	data, err := msg.Marshal()
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	
	// Unmarshal to verify
	var decoded Message
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}
	
	if !reflect.DeepEqual(*msg, decoded) {
		t.Errorf("Marshal/Unmarshal mismatch: got %+v, want %+v", decoded, *msg)
	}
}

func TestConnectionState_String(t *testing.T) {
	tests := []struct {
		state ConnectionState
		want  string
	}{
		{StateDisconnected, "disconnected"},
		{StateConnecting, "connecting"},
		{StateConnected, "connected"},
		{StateReconnecting, "reconnecting"},
		{ConnectionState(999), "unknown"},
	}
	
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.state.String(); got != tt.want {
				t.Errorf("ConnectionState.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMessageHandlerFunc(t *testing.T) {
	called := false
	var receivedMsg *Message
	
	handler := MessageHandlerFunc(func(msg *Message) error {
		called = true
		receivedMsg = msg
		return nil
	})
	
	testMsg := &Message{
		Header: MessageHeader{
			From: "test",
			To:   "test2",
		},
		Body: MessageBody{
			Content: "test content",
		},
	}
	
	err := handler.HandleMessage(testMsg)
	if err != nil {
		t.Errorf("HandleMessage() error = %v", err)
	}
	
	if !called {
		t.Error("Handler function was not called")
	}
	
	if receivedMsg != testMsg {
		t.Error("Handler received different message")
	}
}

func TestBaseExtendedMessage(t *testing.T) {
	baseMsg := &Message{
		ID: 789,
		Header: MessageHeader{
			From: "ext1",
			To:   "ext2",
		},
		Body: MessageBody{
			Content: "extended content",
		},
	}
	
	extMsg := &BaseExtendedMessage{}
	
	// Test SetBaseMessage
	extMsg.SetBaseMessage(baseMsg)
	
	// Test GetBaseMessage
	got := extMsg.GetBaseMessage()
	if got != baseMsg {
		t.Errorf("GetBaseMessage() = %v, want %v", got, baseMsg)
	}
}

func TestUser(t *testing.T) {
	now := time.Now()
	user := User{
		UserID:          "user123",
		Username:        "testuser",
		PublicKey:       "pubkey456",
		X25519PublicKey: "x25519key789",
		CreatedAt:       now,
	}
	
	// Test JSON marshaling
	data, err := json.Marshal(user)
	if err != nil {
		t.Fatalf("Failed to marshal User: %v", err)
	}
	
	var decoded User
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal User: %v", err)
	}
	
	// Compare fields (time comparison needs special handling)
	if decoded.UserID != user.UserID ||
		decoded.Username != user.Username ||
		decoded.PublicKey != user.PublicKey ||
		decoded.X25519PublicKey != user.X25519PublicKey ||
		!decoded.CreatedAt.Equal(user.CreatedAt) {
		t.Errorf("User marshal/unmarshal mismatch: got %+v, want %+v", decoded, user)
	}
}

func TestRegistrationRequest(t *testing.T) {
	req := RegistrationRequest{
		UserID:          "newuser",
		Username:        "New User",
		PublicKey:       "newpubkey",
		X25519PublicKey: "newx25519key",
	}
	
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal RegistrationRequest: %v", err)
	}
	
	var decoded RegistrationRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal RegistrationRequest: %v", err)
	}
	
	if !reflect.DeepEqual(req, decoded) {
		t.Errorf("RegistrationRequest mismatch: got %+v, want %+v", decoded, req)
	}
}

func TestLoginRequest(t *testing.T) {
	req := LoginRequest{
		UserID: "loginuser",
	}
	
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal LoginRequest: %v", err)
	}
	
	var decoded LoginRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal LoginRequest: %v", err)
	}
	
	if req.UserID != decoded.UserID {
		t.Errorf("LoginRequest UserID mismatch: got %v, want %v", decoded.UserID, req.UserID)
	}
}

func TestChallengeResponse(t *testing.T) {
	resp := ChallengeResponse{
		Challenge: "challenge123abc",
	}
	
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Failed to marshal ChallengeResponse: %v", err)
	}
	
	var decoded ChallengeResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal ChallengeResponse: %v", err)
	}
	
	if resp.Challenge != decoded.Challenge {
		t.Errorf("ChallengeResponse Challenge mismatch: got %v, want %v", decoded.Challenge, resp.Challenge)
	}
}

func TestLoginVerifyRequest(t *testing.T) {
	req := LoginVerifyRequest{
		UserID:    "verifyuser",
		Signature: "signature123",
	}
	
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal LoginVerifyRequest: %v", err)
	}
	
	var decoded LoginVerifyRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal LoginVerifyRequest: %v", err)
	}
	
	if !reflect.DeepEqual(req, decoded) {
		t.Errorf("LoginVerifyRequest mismatch: got %+v, want %+v", decoded, req)
	}
}

func TestTokenResponse(t *testing.T) {
	resp := TokenResponse{
		Token: "jwt.token.here",
	}
	
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Failed to marshal TokenResponse: %v", err)
	}
	
	var decoded TokenResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal TokenResponse: %v", err)
	}
	
	if resp.Token != decoded.Token {
		t.Errorf("TokenResponse Token mismatch: got %v, want %v", decoded.Token, resp.Token)
	}
}

func TestUserStatusResponse(t *testing.T) {
	resp := UserStatusResponse{
		Online:  []string{"user1", "user2", "user3"},
		Offline: []string{"user4", "user5"},
	}
	
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Failed to marshal UserStatusResponse: %v", err)
	}
	
	var decoded UserStatusResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal UserStatusResponse: %v", err)
	}
	
	if !reflect.DeepEqual(resp.Online, decoded.Online) {
		t.Errorf("Online users mismatch: got %v, want %v", decoded.Online, resp.Online)
	}
	
	if !reflect.DeepEqual(resp.Offline, decoded.Offline) {
		t.Errorf("Offline users mismatch: got %v, want %v", decoded.Offline, resp.Offline)
	}
}

func TestUserExistsResponse(t *testing.T) {
	tests := []struct {
		name   string
		exists bool
	}{
		{"exists", true},
		{"not exists", false},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := UserExistsResponse{
				Exists: tt.exists,
			}
			
			data, err := json.Marshal(resp)
			if err != nil {
				t.Fatalf("Failed to marshal UserExistsResponse: %v", err)
			}
			
			var decoded UserExistsResponse
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("Failed to unmarshal UserExistsResponse: %v", err)
			}
			
			if resp.Exists != decoded.Exists {
				t.Errorf("UserExistsResponse Exists mismatch: got %v, want %v", decoded.Exists, resp.Exists)
			}
		})
	}
}

func TestMessageHeader_EncryptionFields(t *testing.T) {
	header := MessageHeader{
		From:            "sender",
		To:              "receiver",
		Timestamp:       time.Now(),
		EncryptedKey:    "encryptedAESKey",
		EncryptionNonce: "nonceValue",
	}
	
	data, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("Failed to marshal MessageHeader: %v", err)
	}
	
	// Check that encryption fields are properly tagged
	jsonStr := string(data)
	if !contains(jsonStr, `"encrypted_key"`) {
		t.Error("encrypted_key field not found in JSON")
	}
	if !contains(jsonStr, `"encryption_nonce"`) {
		t.Error("encryption_nonce field not found in JSON")
	}
	
	var decoded MessageHeader
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal MessageHeader: %v", err)
	}
	
	if decoded.EncryptedKey != header.EncryptedKey {
		t.Errorf("EncryptedKey mismatch: got %v, want %v", decoded.EncryptedKey, header.EncryptedKey)
	}
	if decoded.EncryptionNonce != header.EncryptionNonce {
		t.Errorf("EncryptionNonce mismatch: got %v, want %v", decoded.EncryptionNonce, header.EncryptionNonce)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && (s[:len(substr)] == substr || contains(s[1:], substr)))
}

func BenchmarkParseMessage(b *testing.B) {
	data := []byte(`{
		"id": 123,
		"header": {
			"from": "user1",
			"to": "user2",
			"timestamp": "2024-01-01T00:00:00Z",
			"signature": "sig123"
		},
		"body": {
			"content": "Hello World"
		},
		"status": "sent"
	}`)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ParseMessage(data)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMessage_Marshal(b *testing.B) {
	msg := &Message{
		ID: 456,
		Header: MessageHeader{
			From:      "sender",
			To:        "receiver",
			Timestamp: time.Now(),
			Signature: "testsig",
		},
		Body: MessageBody{
			Content: "Test content for benchmarking",
		},
		Status: "delivered",
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := msg.Marshal()
		if err != nil {
			b.Fatal(err)
		}
	}
}