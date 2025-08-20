package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"websocketserver/auth"
	"websocketserver/config"
	"websocketserver/db"
	"websocketserver/handlers"
	"websocketserver/metrics"
	"websocketserver/ws"
)

// CustomStatusHandler - Example custom handler that returns system status
type CustomStatusHandler struct {
	startTime time.Time
}

func (h *CustomStatusHandler) Handle(ctx context.Context, server *ws.Server, sender string, params json.RawMessage) (interface{}, error) {
	// Calculate uptime
	uptime := time.Since(h.startTime)

	// Get memory stats (simplified example)
	return map[string]interface{}{
		"status":         "healthy",
		"uptime_seconds": int(uptime.Seconds()),
		"uptime_human":   uptime.String(),
		"sender":         sender,
		"timestamp":      time.Now().Unix(),
	}, nil
}

// UserListHandler - Returns list of all connected users
type UserListHandler struct{}

func (h *UserListHandler) Handle(ctx context.Context, server *ws.Server, sender string, params json.RawMessage) (interface{}, error) {
	// This is a simplified example - in production you'd want proper access to server internals
	// For now, we'll return a mock response
	return map[string]interface{}{
		"users":     []string{sender}, // In real implementation, get from server.clients
		"requester": sender,
	}, nil
}

// MathHandler - Performs simple math operations
type MathHandler struct{}

type MathParams struct {
	Operation string  `json:"operation"` // "add", "subtract", "multiply", "divide"
	A         float64 `json:"a"`
	B         float64 `json:"b"`
}

func (h *MathHandler) Handle(ctx context.Context, server *ws.Server, sender string, params json.RawMessage) (interface{}, error) {
	var mathParams MathParams
	if err := json.Unmarshal(params, &mathParams); err != nil {
		return nil, fmt.Errorf("invalid parameters: %w", err)
	}

	var result float64
	switch mathParams.Operation {
	case "add":
		result = mathParams.A + mathParams.B
	case "subtract":
		result = mathParams.A - mathParams.B
	case "multiply":
		result = mathParams.A * mathParams.B
	case "divide":
		if mathParams.B == 0 {
			return nil, fmt.Errorf("division by zero")
		}
		result = mathParams.A / mathParams.B
	default:
		return nil, fmt.Errorf("unknown operation: %s", mathParams.Operation)
	}

	return map[string]interface{}{
		"operation": mathParams.Operation,
		"a":         mathParams.A,
		"b":         mathParams.B,
		"result":    result,
	}, nil
}

// EchoDelayedHandler - Echoes back after a delay (demonstrates async handling)
type EchoDelayedHandler struct{}

type EchoDelayedParams struct {
	Message string `json:"message"`
	Delay   int    `json:"delay_ms"` // Delay in milliseconds
}

func (h *EchoDelayedHandler) Handle(ctx context.Context, server *ws.Server, sender string, params json.RawMessage) (interface{}, error) {
	var echoParams EchoDelayedParams
	if err := json.Unmarshal(params, &echoParams); err != nil {
		return nil, fmt.Errorf("invalid parameters: %w", err)
	}

	// Limit delay to 5 seconds max
	if echoParams.Delay > 5000 {
		echoParams.Delay = 5000
	}

	// Wait for the specified delay
	select {
	case <-time.After(time.Duration(echoParams.Delay) * time.Millisecond):
		// Continue after delay
	case <-ctx.Done():
		return nil, fmt.Errorf("request cancelled")
	}

	return map[string]interface{}{
		"echoed_message": echoParams.Message,
		"delay_ms":       echoParams.Delay,
		"sender":         sender,
		"timestamp":      time.Now().Unix(),
	}, nil
}

func main() {
	log.Println("Starting WebSocket Server with Custom Server Message Handlers...")

	// Load configuration
	cfg := config.LoadConfig()

	// Override for local testing
	if cfg.ServerAddr == ":443" {
		cfg.ServerAddr = ":8443"
		log.Printf("Running on development port %s", cfg.ServerAddr)
	}

	// Initialize database
	database, err := db.Initialize("example_app.db")
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer database.Close()

	// Run migrations
	if err := db.RunMigrations(database); err != nil {
		log.Fatalf("Failed to run migrations: %v", err)
	}

	metrics.InitPersistence(database)

	// Initialize services
	authService := auth.NewService(database, cfg.SecurityLogFile)
	wsServer := ws.NewServer(
		database,
		authService,
		cfg.MessageRateLimit,
		cfg.MessageBurstLimit,
		cfg.AllowedOrigins,
	)

	// Register custom server message handlers
	startTime := time.Now()

	// Register custom handlers
	if err := wsServer.RegisterServerHandler("system_status", &CustomStatusHandler{startTime: startTime}); err != nil {
		log.Printf("Failed to register system_status handler: %v", err)
	} else {
		log.Println("Registered custom handler: system_status")
	}

	if err := wsServer.RegisterServerHandler("list_users", &UserListHandler{}); err != nil {
		log.Printf("Failed to register list_users handler: %v", err)
	} else {
		log.Println("Registered custom handler: list_users")
	}

	if err := wsServer.RegisterServerHandler("math", &MathHandler{}); err != nil {
		log.Printf("Failed to register math handler: %v", err)
	} else {
		log.Println("Registered custom handler: math")
	}

	if err := wsServer.RegisterServerHandler("echo_delayed", &EchoDelayedHandler{}); err != nil {
		log.Printf("Failed to register echo_delayed handler: %v", err)
	} else {
		log.Println("Registered custom handler: echo_delayed")
	}

	// Setup routes
	mux := http.NewServeMux()
	handlers.SetupRoutes(mux, database, authService, wsServer)

	// Add a simple info endpoint
	mux.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"server": "WebSocket Server with Custom Handlers",
			"handlers": []string{
				"ping", "echo", "server_info", "user_count", "list_commands", // built-in
				"system_status", "list_users", "math", "echo_delayed", // custom
			},
		})
	})

	// For development, use self-signed certificates
	certFile := "server.crt"
	keyFile := "server.key"

	// Check if certificates exist, if not, provide instructions
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		log.Println("Certificate files not found. Generating self-signed certificates...")
		// In production, you'd use proper certificates
		// For this example, we'll use HTTP instead
		cfg.ServerAddr = strings.Replace(cfg.ServerAddr, ":8443", ":8080", 1)
		log.Printf("Falling back to HTTP on %s", cfg.ServerAddr)

		httpSrv := &http.Server{
			Addr:    cfg.ServerAddr,
			Handler: mux,
		}

		go func() {
			log.Printf("Starting HTTP server on %s", cfg.ServerAddr)
			log.Println("\n=== Server Message Handlers Available ===")
			log.Println("Built-in: ping, echo, server_info, user_count, list_commands")
			log.Println("Custom: system_status, list_users, math, echo_delayed")
			log.Println("=========================================\n")
			if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("HTTP server error: %v", err)
			}
		}()

		// Wait for termination signal
		quit := make(chan os.Signal, 1)
		signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
		<-quit
		log.Println("Shutting down server...")

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := httpSrv.Shutdown(ctx); err != nil {
			log.Printf("Server forced to shutdown: %v", err)
		}
	} else {
		// HTTPS server
		httpsSrv := &http.Server{
			Addr:    cfg.ServerAddr,
			Handler: mux,
		}

		go func() {
			log.Printf("Starting HTTPS server on %s", cfg.ServerAddr)
			log.Println("\n=== Server Message Handlers Available ===")
			log.Println("Built-in: ping, echo, server_info, user_count, list_commands")
			log.Println("Custom: system_status, list_users, math, echo_delayed")
			log.Println("=========================================\n")
			if err := httpsSrv.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
				log.Fatalf("HTTPS server error: %v", err)
			}
		}()

		// HTTP redirect server
		httpSrv := &http.Server{
			Addr: ":8080",
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				host := strings.Split(r.Host, ":")[0]
				target := "https://" + host + ":8443" + r.URL.RequestURI()
				http.Redirect(w, r, target, http.StatusPermanentRedirect)
			}),
		}

		go func() {
			log.Printf("Starting HTTP redirect server on :8080")
			if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("HTTP redirect server error: %v", err)
			}
		}()

		// Wait for termination signal
		quit := make(chan os.Signal, 1)
		signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
		<-quit
		log.Println("Shutting down servers...")

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		httpsSrv.Shutdown(ctx)
		httpSrv.Shutdown(ctx)
	}
}
