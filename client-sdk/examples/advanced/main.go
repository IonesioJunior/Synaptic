package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	client "github.com/IonesioJunior/Synaptic/client-sdk"
	"github.com/IonesioJunior/Synaptic/client-sdk/extensions"
	"github.com/IonesioJunior/Synaptic/client-sdk/types"
)

// Custom message types for a game application
type GameAction struct {
	types.BaseExtendedMessage
	Type   string      `json:"type"`
	Action string      `json:"action"`
	Data   interface{} `json:"data"`
}

type PlayerMove struct {
	PlayerID string `json:"player_id"`
	X        int    `json:"x"`
	Y        int    `json:"y"`
	Score    int    `json:"score"`
}

// Game message handler
type GameHandler struct {
	playerScores map[string]*atomic.Int32
}

func NewGameHandler() *GameHandler {
	return &GameHandler{
		playerScores: make(map[string]*atomic.Int32),
	}
}

func (gh *GameHandler) HandleTypedMessage(msgType string, msg types.ExtendedMessage) error {
	gameMsg, ok := msg.(*GameAction)
	if !ok {
		return fmt.Errorf("invalid game message type")
	}

	switch gameMsg.Action {
	case "move":
		if moveData, ok := gameMsg.Data.(*PlayerMove); ok {
			gh.handlePlayerMove(moveData)
		}
	case "score":
		if moveData, ok := gameMsg.Data.(*PlayerMove); ok {
			gh.updateScore(moveData.PlayerID, moveData.Score)
		}
	}

	return nil
}

func (gh *GameHandler) handlePlayerMove(move *PlayerMove) {
	fmt.Printf("[GAME] Player %s moved to (%d, %d)\n", move.PlayerID, move.X, move.Y)
}

func (gh *GameHandler) updateScore(playerID string, score int) {
	if _, exists := gh.playerScores[playerID]; !exists {
		gh.playerScores[playerID] = &atomic.Int32{}
	}
	gh.playerScores[playerID].Add(int32(score))
	fmt.Printf("[GAME] Player %s score: %d\n", playerID, gh.playerScores[playerID].Load())
}

func (gh *GameHandler) GetSupportedTypes() []string {
	return []string{"game"}
}

// Metrics collector
type MetricsCollector struct {
	messageCount atomic.Uint64
	errorCount   atomic.Uint64
	startTime    time.Time
}

func NewMetricsCollector() *MetricsCollector {
	return &MetricsCollector{
		startTime: time.Now(),
	}
}

func (mc *MetricsCollector) HandleMessage(msg *types.Message) error {
	mc.messageCount.Add(1)

	// Log every 10th message
	if count := mc.messageCount.Load(); count%10 == 0 {
		uptime := time.Since(mc.startTime)
		rate := float64(count) / uptime.Seconds()
		fmt.Printf("[METRICS] Messages: %d, Rate: %.2f msg/s, Errors: %d\n",
			count, rate, mc.errorCount.Load())
	}

	return nil
}

// Priority message filter
func createPriorityFilter(priorityUsers []string) func(*types.Message) bool {
	userMap := make(map[string]bool)
	for _, user := range priorityUsers {
		userMap[user] = true
	}

	return func(msg *types.Message) bool {
		return userMap[msg.Header.From]
	}
}

func main() {
	// Configuration
	serverURL := os.Getenv("WS_SERVER_URL")
	if serverURL == "" {
		serverURL = "http://localhost:443"
	}

	userID := os.Getenv("WS_USER_ID")
	if userID == "" {
		userID = "advanced-client-" + fmt.Sprintf("%d", time.Now().Unix())
	}

	// Create client with advanced configuration
	config := &client.Config{
		ServerURL:         serverURL,
		UserID:            userID,
		Username:          "Advanced Client",
		AutoReconnect:     true,
		MaxReconnectWait:  30 * time.Second,
		MessageBufferSize: 500,
		Workers:           20,
		Debug:             os.Getenv("DEBUG") == "true",
	}

	c, err := client.NewClient(config)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer c.Disconnect()

	// Create message router for custom types
	router := extensions.NewMessageRouter()
	factory := extensions.NewDefaultMessageFactory()
	factory.RegisterType("game", &GameAction{})
	router.SetFactory(factory)

	// Register game handler
	gameHandler := NewGameHandler()
	router.RegisterHandler("game", gameHandler)

	// Create chained handler
	chainedHandler := extensions.NewChainedHandler()

	// Add metrics collector
	metricsCollector := NewMetricsCollector()
	chainedHandler.AddHandler(metricsCollector)

	// Add priority filter for important users
	priorityUsers := []string{"admin", "moderator", "vip"}
	priorityHandler := extensions.NewFilteredHandler(
		createPriorityFilter(priorityUsers),
		types.MessageHandlerFunc(func(msg *types.Message) error {
			fmt.Printf("[PRIORITY] Message from %s: %s\n",
				msg.Header.From, msg.Body.Content)
			return nil
		}),
	)
	chainedHandler.AddHandler(priorityHandler)

	// Add async handler for heavy processing
	asyncHandler := extensions.NewAsyncHandler(
		types.MessageHandlerFunc(func(msg *types.Message) error {
			// Simulate heavy processing
			if msg.Header.IsBroadcast {
				time.Sleep(100 * time.Millisecond)
				fmt.Printf("[ASYNC] Processed broadcast from %s\n", msg.Header.From)
			}
			return nil
		}),
		100, // Queue size
		5,   // Workers
	)
	defer asyncHandler.Stop()
	chainedHandler.AddHandler(asyncHandler)

	// Add router to chain
	chainedHandler.AddHandler(router)

	// Register the chained handler with client
	c.AddMessageHandler(chainedHandler)

	// Set up connection callbacks
	c.OnConnect(func() {
		log.Println("✓ Connected to server")

		// Send initial presence
		c.Broadcast("Advanced client online")

		// Start sending periodic game updates
		go sendPeriodicGameUpdates(c)
	})

	c.OnDisconnect(func(err error) {
		log.Printf("✗ Disconnected: %v", err)
		metricsCollector.errorCount.Add(1)
	})

	c.OnReconnect(func(attempt int) {
		log.Printf("↻ Reconnecting (attempt %d)...", attempt)
	})

	// Connect to server
	log.Println("Connecting to server...")
	if err := c.Connect(); err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}

	// Monitor channels
	go monitorChannels(c)

	// Set up graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Print status periodically
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	log.Println("Advanced client running. Press Ctrl+C to exit.")

	for {
		select {
		case <-sigChan:
			log.Println("Shutting down...")

			// Send goodbye message
			c.Broadcast("Advanced client going offline")
			time.Sleep(500 * time.Millisecond)

			return

		case <-ticker.C:
			// Print client metrics
			sent, received, reconnects, errors := c.GetMetrics()
			log.Printf("[STATUS] State: %s, Sent: %d, Received: %d, Reconnects: %d, Errors: %d",
				c.GetState(), sent, received, reconnects, errors)

		case <-ctx.Done():
			return
		}
	}
}

func sendPeriodicGameUpdates(c *client.Client) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	playerID := c.GetState().String()
	x, y := 0, 0

	for range ticker.C {
		if !c.IsConnected() {
			continue
		}

		// Create game action
		x = (x + 1) % 100
		y = (y + 1) % 100

		gameMsg := GameAction{
			Type:   "game",
			Action: "move",
			Data: PlayerMove{
				PlayerID: playerID,
				X:        x,
				Y:        y,
				Score:    x + y,
			},
		}

		// Marshal and send
		data, err := json.Marshal(gameMsg)
		if err != nil {
			log.Printf("Failed to marshal game message: %v", err)
			continue
		}

		// Send as broadcast (in real app, might be targeted)
		if err := c.Broadcast(string(data)); err != nil {
			log.Printf("Failed to send game update: %v", err)
		}
	}
}

func monitorChannels(c *client.Client) {
	receiveChan := c.GetReceiveChannel()
	errorChan := c.GetErrorChannel()

	for {
		select {
		case msg := <-receiveChan:
			// Process received messages
			if msg.Header.From == c.GetState().String() {
				continue // Skip own messages
			}

			// Try to parse as game message
			var gameMsg GameAction
			if err := json.Unmarshal([]byte(msg.Body.Content), &gameMsg); err == nil {
				log.Printf("[RECEIVED] Game action from %s: %s",
					msg.Header.From, gameMsg.Action)
			}

		case err := <-errorChan:
			log.Printf("[ERROR] %v", err)
		}
	}
}
