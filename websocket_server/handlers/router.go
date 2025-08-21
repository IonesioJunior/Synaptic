package handlers

import (
	"database/sql"
	"net/http"

	"websocketserver/auth"
	"websocketserver/ws"
)

// SetupRoutes configures all HTTP routes for the application
func SetupRoutes(mux *http.ServeMux, database *sql.DB, authService *auth.Service, wsServer *ws.Server) {
	// Health check endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"healthy","service":"websocket-server"}`))
	})

	// WebSocket routes
	mux.HandleFunc("/ws", wsServer.HandleWebSocket)
	mux.HandleFunc("/active-users", wsServer.ActiveUsersHandler)

	// Authentication routes
	mux.HandleFunc("/auth/register", authService.HandleRegistration)
	mux.HandleFunc("/auth/login", authService.HandleLogin)
	mux.HandleFunc("/auth/check-userid/", authService.HandleCheckUserID)
	mux.HandleFunc("/auth/users/", authService.HandleGetUserInfo)

	// Static file serving (keeping only for basic assets like favicon)
	fs := http.FileServer(http.Dir("static"))
	mux.Handle("/static/", http.StripPrefix("/static/", fs))
}
