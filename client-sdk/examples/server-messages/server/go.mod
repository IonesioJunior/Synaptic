module server-messages-example

go 1.23.0

toolchain go1.24.1

replace websocketserver => ../../../../websocket_server

require websocketserver v0.0.0-00010101000000-000000000000

require (
	github.com/golang-jwt/jwt/v5 v5.2.2 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/mattn/go-sqlite3 v1.14.27 // indirect
)
