module server-messages-example

go 1.21

replace websocketserver => ../../../websocket_server

require (
	websocketserver v0.0.0-00010101000000-000000000000
)

require (
	github.com/DATA-DOG/go-sqlmock v1.5.2 // indirect
	github.com/golang-jwt/jwt/v5 v5.2.2 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/mattn/go-sqlite3 v1.14.27 // indirect
)