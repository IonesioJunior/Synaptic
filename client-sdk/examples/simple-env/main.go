package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	client "github.com/IonesioJunior/Synaptic/client-sdk"
	"github.com/IonesioJunior/Synaptic/client-sdk/types"
)

func main() {
	// Get configuration from environment
	serverURL := os.Getenv("WS_SERVER_URL")
	if serverURL == "" {
		serverURL = "https://localhost:443"
	}

	userID := os.Getenv("WS_USER_ID")
	if userID == "" {
		log.Fatal("WS_USER_ID environment variable is required")
	}

	username := os.Getenv("WS_USERNAME")
	if username == "" {
		username = userID // Use userID as username if not provided
	}

	// Handle private key - either from environment or generate new one
	var privateKeyBase64 string
	privateKeyEnv := os.Getenv("WS_PRIVATE_KEY")

	if privateKeyEnv != "" {
		// Use existing private key
		privateKeyBase64 = privateKeyEnv
		log.Printf("Using existing private key for %s", userID)
	} else {
		// Generate new key pair
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			log.Fatalf("Failed to generate keys: %v", err)
		}
		privateKeyBase64 = base64.StdEncoding.EncodeToString(priv)
		publicKeyBase64 := base64.StdEncoding.EncodeToString(pub)

		log.Printf("Generated new key pair for %s", userID)
		log.Printf("Private key (save this): %s", privateKeyBase64)
		log.Printf("Public key: %s", publicKeyBase64)
		log.Println("To reuse this identity, set WS_PRIVATE_KEY environment variable")
	}

	fmt.Printf("Connecting as %s (%s)\n", username, userID)

	// Create client configuration
	config := &client.Config{
		ServerURL:        serverURL,
		UserID:           userID,
		Username:         username,
		PrivateKey:       privateKeyBase64,
		AutoReconnect:    true,
		Debug:            os.Getenv("DEBUG") == "true",
		InsecureTLS:      os.Getenv("INSECURE_TLS") == "true",
		EncryptionPolicy: client.EncryptionPreferred, // Enable encryption for direct messages
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
		encrypted := ""
		if msg.Header.Signature != "" {
			if valid, _ := c.VerifyMessageSignature(msg); valid {
				verified = " [VERIFIED]"
			}
		}
		// Message was encrypted if it has an encrypted key
		if msg.Header.EncryptedKey != "" {
			encrypted = " [ENCRYPTED]"
		}

		fmt.Printf("\n[%s] %s -> %s%s%s: %s\n",
			msg.Header.Timestamp.Format("15:04:05"),
			msg.Header.From,
			msg.Header.To,
			verified,
			encrypted,
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

		// Send initial presence message if configured
		if os.Getenv("AUTO_ANNOUNCE") == "true" {
			c.Broadcast(fmt.Sprintf("%s is now online", username))
		}
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

	// If AUTO_MODE is set, run in automated mode
	if os.Getenv("AUTO_MODE") == "true" {
		fmt.Println("Running in auto mode - sending periodic messages")
		// Send a message every 30 seconds
		for {
			time.Sleep(30 * time.Second)
			msg := fmt.Sprintf("Auto message from %s at %s", username, time.Now().Format("15:04:05"))
			c.Broadcast(msg)
		}
	}

	// Command loop for interactive mode
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

		case strings.HasPrefix(input, "direct "):
			// Alternative direct message format
			parts := strings.SplitN(input[7:], " ", 2)
			if len(parts) != 2 {
				fmt.Println("Usage: direct <user> <message>")
			} else {
				recipient := strings.TrimSpace(parts[0])
				message := strings.TrimSpace(parts[1])
				if err := c.SendMessage(recipient, message, true); err != nil {
					fmt.Printf("Failed to send message: %v\n", err)
				} else {
					fmt.Printf("→ Sent encrypted message to %s\n", recipient)
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
