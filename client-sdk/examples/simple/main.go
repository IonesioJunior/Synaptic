package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"

	client "github.com/IonesioJunior/Synaptic/client-sdk"
	"github.com/IonesioJunior/Synaptic/client-sdk/types"
)

func main() {
	// Get server URL from environment or use default
	serverURL := os.Getenv("WS_SERVER_URL")
	if serverURL == "" {
		serverURL = "http://localhost:443"
	}

	// Get user credentials from environment or prompt
	userID := os.Getenv("WS_USER_ID")
	username := os.Getenv("WS_USERNAME")

	// If not provided via environment, prompt for input
	if userID == "" || username == "" {
		reader := bufio.NewReader(os.Stdin)

		if userID == "" {
			fmt.Print("Enter user ID: ")
			userID, _ = reader.ReadString('\n')
			userID = strings.TrimSpace(userID)
		}

		if username == "" {
			fmt.Print("Enter username: ")
			username, _ = reader.ReadString('\n')
			username = strings.TrimSpace(username)
		}
	} else {
		fmt.Printf("Connecting as %s (%s)\n", username, userID)
	}

	// Create client configuration
	config := &client.Config{
		ServerURL:     serverURL,
		UserID:        userID,
		Username:      username,
		AutoReconnect: true,
		Debug:         true,
		InsecureTLS:   os.Getenv("INSECURE_TLS") == "true", // Allow insecure TLS for development
	}

	// Create client
	c, err := client.NewClient(config)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer c.Disconnect()

	// Add message handler
	c.AddMessageHandlerFunc(func(msg *types.Message) error {
		verified := ""
		if msg.Header.Signature != "" {
			if valid, _ := c.VerifyMessageSignature(msg); valid {
				verified = " [VERIFIED]"
			}
		}

		fmt.Printf("\n[%s] %s -> %s%s: %s\n",
			msg.Header.Timestamp.Format("15:04:05"),
			msg.Header.From,
			msg.Header.To,
			verified,
			msg.Body.Content)
		fmt.Print("> ")
		return nil
	})

	// Set connection callbacks
	c.OnConnect(func() {
		fmt.Println("✓ Connected to server")
		fmt.Println("\nCommands:")
		fmt.Println("  @<user> <message>  - Send direct message")
		fmt.Println("  !<message>         - Broadcast message")
		fmt.Println("  /users             - List online users")
		fmt.Println("  /quit              - Exit")
		fmt.Println()
	})

	c.OnDisconnect(func(err error) {
		fmt.Printf("\n✗ Disconnected: %v\n", err)
	})

	c.OnReconnect(func(attempt int) {
		fmt.Printf("\n↻ Reconnecting (attempt %d)...\n", attempt)
	})

	// Connect to server
	fmt.Println("Connecting to server...")
	if err := c.Connect(); err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}

	// Command loop
	fmt.Print("> ")
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		input := strings.TrimSpace(scanner.Text())

		if input == "" {
			fmt.Print("> ")
			continue
		}

		switch {
		case input == "/quit":
			fmt.Println("Goodbye!")
			return

		case input == "/users":
			// This would require implementing an API call to get active users
			fmt.Println("Feature not implemented in this example")

		case strings.HasPrefix(input, "@"):
			// Direct message
			parts := strings.SplitN(input[1:], " ", 2)
			if len(parts) != 2 {
				fmt.Println("Usage: @<user> <message>")
			} else {
				recipient := strings.TrimSpace(parts[0])
				message := strings.TrimSpace(parts[1])
				if err := c.SendMessage(recipient, message, true); err != nil {
					fmt.Printf("Failed to send message: %v\n", err)
				} else {
					fmt.Printf("→ Sent to %s\n", recipient)
				}
			}

		case strings.HasPrefix(input, "!"):
			// Broadcast
			message := strings.TrimSpace(input[1:])
			if message == "" {
				fmt.Println("Usage: !<message>")
			} else {
				if err := c.Broadcast(message); err != nil {
					fmt.Printf("Failed to broadcast: %v\n", err)
				} else {
					fmt.Println("→ Broadcasted")
				}
			}

		default:
			fmt.Println("Unknown command. Use /quit to exit.")
		}

		fmt.Print("> ")
	}

	if err := scanner.Err(); err != nil {
		log.Printf("Scanner error: %v", err)
	}
}
