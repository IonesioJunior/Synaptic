package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
)

// Message structures
type MessageHeader struct {
	From        string    `json:"from"`
	To          string    `json:"to"`
	MessageType string    `json:"message_type"`
	Timestamp   time.Time `json:"timestamp"`
	Signature   string    `json:"signature,omitempty"`
}

type MessageBody struct {
	Content string `json:"content"`
}

type Message struct {
	Header MessageHeader `json:"header"`
	Body   MessageBody   `json:"body"`
}

type ServerCommand struct {
	Command   string      `json:"command"`
	Params    interface{} `json:"params,omitempty"`
	RequestID string      `json:"request_id,omitempty"`
}

type ServerResponse struct {
	Success   bool        `json:"success"`
	RequestID string      `json:"request_id,omitempty"`
	Result    interface{} `json:"result,omitempty"`
	Error     string      `json:"error,omitempty"`
}

// ExampleClient demonstrates server message functionality
type ExampleClient struct {
	userID     string
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
	conn       *websocket.Conn
	token      string
	serverURL  string
}

func NewExampleClient(userID, serverURL string) (*ExampleClient, error) {
	// Generate keypair
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate keypair: %w", err)
	}

	return &ExampleClient{
		userID:     userID,
		publicKey:  publicKey,
		privateKey: privateKey,
		serverURL:  serverURL,
	}, nil
}

func (c *ExampleClient) Register() error {
	// Register user
	// regURL := c.serverURL + "/auth/register"

	payload := map[string]string{
		"user_id":    c.userID,
		"username":   c.userID,
		"public_key": base64.StdEncoding.EncodeToString(c.publicKey),
	}

	payloadJSON, _ := json.Marshal(payload)

	fmt.Printf("Registering user %s...\n", c.userID)
	fmt.Printf("Registration payload: %s\n", string(payloadJSON))

	// In a real implementation, you'd make an HTTP POST request
	// For this example, we'll assume registration is successful
	fmt.Printf("✓ User %s registered successfully\n\n", c.userID)

	return nil
}

func (c *ExampleClient) Login() error {
	fmt.Printf("Logging in user %s...\n", c.userID)

	// In a real implementation, you'd:
	// 1. Request challenge from /auth/login
	// 2. Sign the challenge with your private key
	// 3. Send signature to /auth/login?verify=true
	// 4. Receive JWT token

	// For this example, we'll create a mock JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": c.userID,
		"exp":     time.Now().Add(24 * time.Hour).Unix(),
	})

	// Sign with a mock secret (in real use, this would be done by the server)
	tokenString, err := token.SignedString([]byte("mock_secret"))
	if err != nil {
		return fmt.Errorf("failed to create token: %w", err)
	}

	c.token = tokenString
	fmt.Printf("✓ Login successful for %s\n\n", c.userID)

	return nil
}

func (c *ExampleClient) Connect() error {
	// Parse WebSocket URL
	wsURL := strings.Replace(c.serverURL, "http", "ws", 1) + "/ws"
	u, err := url.Parse(wsURL)
	if err != nil {
		return fmt.Errorf("invalid WebSocket URL: %w", err)
	}

	// Add token to query parameters
	q := u.Query()
	q.Set("token", c.token)
	u.RawQuery = q.Encode()

	fmt.Printf("Connecting to WebSocket: %s\n", u.String())

	// Connect to WebSocket
	conn, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		return fmt.Errorf("failed to connect to WebSocket: %w", err)
	}

	c.conn = conn
	fmt.Printf("✓ Connected to WebSocket server\n\n")

	// Start message reader
	go c.readMessages()

	return nil
}

func (c *ExampleClient) readMessages() {
	defer c.conn.Close()

	for {
		_, data, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("WebSocket connection closed: %v", err)
			} else {
				log.Printf("Read error: %v", err)
			}
			break
		}

		var msg Message
		if err := json.Unmarshal(data, &msg); err != nil {
			log.Printf("Failed to unmarshal message: %v", err)
			continue
		}

		// Check if this is a server response
		if msg.Header.From == "server" {
			var response ServerResponse
			if err := json.Unmarshal([]byte(msg.Body.Content), &response); err != nil {
				log.Printf("Failed to unmarshal server response: %v", err)
				continue
			}

			fmt.Printf("\n🤖 Server Response:\n")
			if response.Success {
				fmt.Printf("   ✓ Success: %s\n", formatJSON(response.Result))
			} else {
				fmt.Printf("   ❌ Error: %s\n", response.Error)
			}
			if response.RequestID != "" {
				fmt.Printf("   Request ID: %s\n", response.RequestID)
			}
		} else {
			fmt.Printf("\n📨 Received message from %s: %s\n", msg.Header.From, msg.Body.Content)
		}
	}
}

func (c *ExampleClient) SendServerMessage(command string, params interface{}, requestID string) error {
	// Create server command
	cmd := ServerCommand{
		Command:   command,
		Params:    params,
		RequestID: requestID,
	}

	cmdJSON, err := json.Marshal(cmd)
	if err != nil {
		return fmt.Errorf("failed to marshal command: %w", err)
	}

	// Sign the command content
	signature := ed25519.Sign(c.privateKey, cmdJSON)

	// Create message
	msg := Message{
		Header: MessageHeader{
			From:        c.userID,
			To:          "server",
			MessageType: "server",
			Timestamp:   time.Now(),
			Signature:   base64.StdEncoding.EncodeToString(signature),
		},
		Body: MessageBody{
			Content: string(cmdJSON),
		},
	}

	// Send message
	msgJSON, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	fmt.Printf("📤 Sending server command: %s\n", command)
	fmt.Printf("   Params: %s\n", formatJSON(params))

	return c.conn.WriteMessage(websocket.TextMessage, msgJSON)
}

func (c *ExampleClient) SendDirectMessage(to, content string) error {
	msg := Message{
		Header: MessageHeader{
			From:        c.userID,
			To:          to,
			MessageType: "direct",
			Timestamp:   time.Now(),
		},
		Body: MessageBody{
			Content: content,
		},
	}

	msgJSON, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	fmt.Printf("📤 Sending direct message to %s: %s\n", to, content)
	return c.conn.WriteMessage(websocket.TextMessage, msgJSON)
}

func (c *ExampleClient) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

func formatJSON(v interface{}) string {
	if v == nil {
		return "null"
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(data)
}

func main() {
	serverURL := "http://localhost:8080"
	if len(os.Args) > 1 {
		serverURL = os.Args[1]
	}

	userID := "demo_user_" + strconv.FormatInt(time.Now().Unix(), 10)

	fmt.Println("=== WebSocket Server Message Example ===")
	fmt.Printf("Server: %s\n", serverURL)
	fmt.Printf("User ID: %s\n\n", userID)

	// Create client
	client, err := NewExampleClient(userID, serverURL)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	// Register and login
	if err := client.Register(); err != nil {
		log.Fatalf("Registration failed: %v", err)
	}

	if err := client.Login(); err != nil {
		log.Fatalf("Login failed: %v", err)
	}

	// Note: In a real scenario, you would connect to the actual server
	fmt.Println("⚠️  This is a demo client showing message structure.")
	fmt.Println("To test with a real server, run the server example first.\n")

	// Show example server messages
	fmt.Println("=== Example Server Messages ===")

	// Example 1: Ping
	fmt.Println("\n1. Ping Command:")
	cmd := ServerCommand{
		Command:   "ping",
		RequestID: "ping-001",
	}
	cmdJSON, _ := json.Marshal(cmd)
	signature := ed25519.Sign(client.privateKey, cmdJSON)

	msg := Message{
		Header: MessageHeader{
			From:        userID,
			To:          "server",
			MessageType: "server",
			Timestamp:   time.Now(),
			Signature:   base64.StdEncoding.EncodeToString(signature),
		},
		Body: MessageBody{
			Content: string(cmdJSON),
		},
	}
	msgJSON, _ := json.MarshalIndent(msg, "", "  ")
	fmt.Printf("Message: %s\n", string(msgJSON))

	// Example 2: Math operation
	fmt.Println("\n2. Math Command:")
	cmd = ServerCommand{
		Command: "math",
		Params: map[string]interface{}{
			"operation": "add",
			"a":         10.5,
			"b":         5.3,
		},
		RequestID: "math-001",
	}
	cmdJSON, _ = json.Marshal(cmd)
	signature = ed25519.Sign(client.privateKey, cmdJSON)

	msg = Message{
		Header: MessageHeader{
			From:        userID,
			To:          "server",
			MessageType: "server",
			Timestamp:   time.Now(),
			Signature:   base64.StdEncoding.EncodeToString(signature),
		},
		Body: MessageBody{
			Content: string(cmdJSON),
		},
	}
	msgJSON, _ = json.MarshalIndent(msg, "", "  ")
	fmt.Printf("Message: %s\n", string(msgJSON))

	// Example 3: Delayed echo
	fmt.Println("\n3. Delayed Echo Command:")
	cmd = ServerCommand{
		Command: "echo_delayed",
		Params: map[string]interface{}{
			"message":  "Hello from client!",
			"delay_ms": 1000,
		},
		RequestID: "echo-001",
	}
	cmdJSON, _ = json.Marshal(cmd)
	signature = ed25519.Sign(client.privateKey, cmdJSON)

	msg = Message{
		Header: MessageHeader{
			From:        userID,
			To:          "server",
			MessageType: "server",
			Timestamp:   time.Now(),
			Signature:   base64.StdEncoding.EncodeToString(signature),
		},
		Body: MessageBody{
			Content: string(cmdJSON),
		},
	}
	msgJSON, _ = json.MarshalIndent(msg, "", "  ")
	fmt.Printf("Message: %s\n", string(msgJSON))

	fmt.Println("\n=== Interactive Mode (if connected to real server) ===")
	fmt.Println("Commands:")
	fmt.Println("  ping                          - Test server connectivity")
	fmt.Println("  echo <text>                   - Echo back text")
	fmt.Println("  info                          - Get server information")
	fmt.Println("  count                         - Get user count")
	fmt.Println("  status                        - Get system status")
	fmt.Println("  math <op> <a> <b>            - Perform math operation")
	fmt.Println("  delay <text> <ms>            - Echo with delay")
	fmt.Println("  direct <user> <message>      - Send direct message")
	fmt.Println("  quit                         - Exit")

	// Check if we can actually connect
	_, err = url.Parse(serverURL)
	if err != nil {
		fmt.Printf("\nInvalid server URL: %v\n", err)
		return
	}

	// Try to connect (this will likely fail in demo mode)
	fmt.Printf("\nAttempting to connect to %s...\n", serverURL)
	err = client.Connect()
	if err != nil {
		fmt.Printf("❌ Connection failed: %v\n", err)
		fmt.Println("\nTo test with a real server:")
		fmt.Println("1. Run: cd ../server && go run main.go")
		fmt.Println("2. In another terminal: cd ../client && go run main.go")
		return
	}

	// Interactive mode
	scanner := bufio.NewScanner(os.Stdin)
	requestCounter := 0

	for {
		fmt.Print("\n> ")
		if !scanner.Scan() {
			break
		}

		input := strings.TrimSpace(scanner.Text())
		if input == "" {
			continue
		}

		parts := strings.Fields(input)
		command := parts[0]

		requestCounter++
		requestID := fmt.Sprintf("req-%d", requestCounter)

		switch command {
		case "quit", "exit":
			fmt.Println("Goodbye!")
			return

		case "ping":
			client.SendServerMessage("ping", nil, requestID)

		case "echo":
			if len(parts) > 1 {
				text := strings.Join(parts[1:], " ")
				client.SendServerMessage("echo", map[string]string{"text": text}, requestID)
			} else {
				client.SendServerMessage("echo", map[string]string{"text": "Hello World"}, requestID)
			}

		case "info":
			client.SendServerMessage("server_info", nil, requestID)

		case "count":
			client.SendServerMessage("user_count", nil, requestID)

		case "status":
			client.SendServerMessage("system_status", nil, requestID)

		case "math":
			if len(parts) >= 4 {
				op := parts[1]
				a, _ := strconv.ParseFloat(parts[2], 64)
				b, _ := strconv.ParseFloat(parts[3], 64)
				params := map[string]interface{}{
					"operation": op,
					"a":         a,
					"b":         b,
				}
				client.SendServerMessage("math", params, requestID)
			} else {
				fmt.Println("Usage: math <operation> <a> <b>")
			}

		case "delay":
			if len(parts) >= 3 {
				text := parts[1]
				delay, _ := strconv.Atoi(parts[2])
				params := map[string]interface{}{
					"message":  text,
					"delay_ms": delay,
				}
				client.SendServerMessage("echo_delayed", params, requestID)
			} else {
				fmt.Println("Usage: delay <text> <delay_ms>")
			}

		case "direct":
			if len(parts) >= 3 {
				to := parts[1]
				message := strings.Join(parts[2:], " ")
				client.SendDirectMessage(to, message)
			} else {
				fmt.Println("Usage: direct <user_id> <message>")
			}

		default:
			fmt.Printf("Unknown command: %s\n", command)
		}
	}
}
