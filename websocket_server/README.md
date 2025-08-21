# WebSocket Server

A high-performance, secure WebSocket server built in Go featuring end-to-end encryption, real-time messaging, and comprehensive user management.

## 🚀 Features

### Core Capabilities
- **End-to-End Encryption**: Hybrid encryption using AES-256-GCM + X25519 for direct messages
- **Real-Time Messaging**: WebSocket-based instant communication with message persistence
- **Authentication**: Ed25519 public-key cryptography with challenge-response protocol
- **Message Types**: Direct messages (encrypted), broadcasts (public), and server commands
- **Rate Limiting**: Token bucket algorithm to prevent abuse (configurable)
- **Analytics**: Session tracking, message metrics, and user engagement analytics
- **Multi-Client Support**: Handle thousands of concurrent connections efficiently

### Security
- ✅ Zero-knowledge architecture - server cannot decrypt private messages
- ✅ Ed25519 signatures for message authentication
- ✅ JWT tokens with 24-hour validity
- ✅ Challenge-response authentication prevents replay attacks
- ✅ TLS/HTTPS support with automatic HTTP→HTTPS redirect
- ✅ Forward secrecy through ephemeral keys

## 📋 Prerequisites

- Go 1.21 or higher
- SQLite3
- OpenSSL (for TLS certificates)
- Docker & Docker Compose (optional)

## 🛠️ Installation

### Option 1: Direct Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/websocket-server.git
cd websocket-server/websocket_server

# Install dependencies
go mod download

# Build the server
go build -o websocket-server .

# Run the server
./websocket-server
```

### Option 2: Docker Installation

```bash
# Build and run with Docker Compose
docker compose up --build

# Or build manually
docker build -t websocket-server .
docker run -p 443:443 -p 80:80 websocket-server
```

## ⚙️ Configuration

Configure the server using environment variables:

```bash
# Server Configuration
SERVER_ADDR=":443"                    # Server address
JWT_SECRET="your-secret-key-min-16"   # JWT signing secret (required)

# Rate Limiting
MESSAGE_RATE_LIMIT="10.0"             # Messages per second (default: 5.0)
MESSAGE_BURST_LIMIT="20"              # Burst capacity (default: 10)

# Security
ALLOWED_ORIGINS="https://example.com" # Comma-separated allowed origins
SECURITY_LOG_FILE="/var/log/ws.log"   # Security audit log path

# Database
DB_PATH="./data/websocket.db"         # SQLite database path
```

### TLS/SSL Setup

For production, place your certificates in the project root:
- `server.crt` - SSL certificate
- `server.key` - Private key

For development, generate self-signed certificates:
```bash
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes
```

## 🏗️ Architecture

### System Components

```
┌─────────────────────────────────────────────┐
│            WebSocket Server                  │
├─────────────────────────────────────────────┤
│  ┌─────────┐  ┌─────────┐  ┌─────────┐    │
│  │  Auth   │  │   WS    │  │   API   │    │
│  │ Handler │  │ Handler │  │ Routes  │    │
│  └────┬────┘  └────┬────┘  └────┬────┘    │
│       └────────────┴────────────┘          │
│                    │                        │
│           ┌────────▼────────┐              │
│           │  Core Server    │              │
│           │   - Sessions    │              │
│           │   - Routing     │              │
│           │   - Rate Limit  │              │
│           └────────┬────────┘              │
│                    │                        │
│  ┌─────────────────▼─────────────────┐    │
│  │          SQLite Database          │    │
│  │  - Users  - Messages  - Sessions  │    │
│  └───────────────────────────────────┘    │
└─────────────────────────────────────────────┘
```

### Database Schema

```sql
-- Users table with encryption keys
CREATE TABLE users (
    user_id TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    public_key TEXT NOT NULL,        -- Ed25519 signing key
    x25519_public_key TEXT,          -- X25519 encryption key
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Messages with encryption support
CREATE TABLE messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_user TEXT NOT NULL,
    to_user TEXT NOT NULL,
    content TEXT NOT NULL,
    encrypted_key TEXT,              -- Encrypted AES key
    encryption_nonce TEXT,           -- AES-GCM nonce
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status TEXT DEFAULT 'pending',
    signature TEXT,
    FOREIGN KEY (from_user) REFERENCES users(user_id)
);
```

## 📡 API Endpoints

### Authentication

#### Register User
```http
POST /auth/register
Content-Type: application/json

{
    "user_id": "alice",
    "username": "Alice Smith",
    "public_key": "base64_ed25519_public_key",
    "x25519_public_key": "base64_x25519_public_key"
}
```

#### Login (Challenge-Response)
```http
# Step 1: Request challenge
POST /auth/login
{
    "user_id": "alice"
}

# Response
{
    "challenge": "base64_random_challenge"
}

# Step 2: Submit signed challenge
POST /auth/login?verify=true
{
    "user_id": "alice",
    "challenge": "base64_random_challenge",
    "signature": "base64_ed25519_signature"
}

# Response
{
    "token": "jwt_token",
    "expires_at": "2024-01-16T10:00:00Z"
}
```

### WebSocket Connection

```javascript
// Connect with JWT token
const ws = new WebSocket('wss://server.com/ws?token=YOUR_JWT_TOKEN');

ws.onmessage = (event) => {
    const message = JSON.parse(event.data);
    console.log('Received:', message);
};
```

### User Management

```http
# Get user info
GET /auth/users/{user_id}
Authorization: Bearer YOUR_JWT_TOKEN

# Check if user exists
GET /auth/check-userid/{user_id}

# Get active users
GET /active-users
```

### Direct Message API

```http
POST /direct-message/
Authorization: Bearer YOUR_JWT_TOKEN
Content-Type: application/json

{
    "to": "bob",
    "content": "Hello Bob!"
}
```

## 💬 Message Format

### Message Structure

```json
{
    "header": {
        "from": "alice",
        "to": "bob",
        "message_type": "direct",
        "timestamp": "2024-01-15T10:30:00Z",
        "signature": "base64_signature",
        "encrypted_key": "base64_encrypted_aes_key",
        "encryption_nonce": "base64_nonce"
    },
    "body": {
        "content": "encrypted_or_plain_content"
    }
}
```

### Message Types

1. **Direct Message** (Encrypted)
   - `message_type: "direct"`
   - End-to-end encrypted with recipient's X25519 public key
   - Server cannot decrypt content

2. **Broadcast Message** (Plain)
   - `message_type: "broadcast"`
   - Sent to all connected users
   - Not encrypted (public by design)

3. **Server Message** (Command)
   - `message_type: "server"`
   - Execute server-side commands
   - Must be signed with sender's Ed25519 key

## 🔐 Encryption Implementation

### Encryption Flow

1. **Key Generation**
   - Each client generates X25519 key pairs
   - Public keys registered with server during authentication

2. **Message Encryption**
   ```
   1. Generate random AES-256 key
   2. Encrypt message with AES-256-GCM
   3. Encrypt AES key with recipient's X25519 public key
   4. Send encrypted content + encrypted key
   ```

3. **Message Decryption**
   ```
   1. Decrypt AES key with X25519 private key
   2. Decrypt message content with AES key
   3. Verify signature if present
   ```

## 🚀 Server Commands

The server supports custom command handlers for server messages:

### Built-in Commands

- `ping` - Health check
- `echo` - Echo parameters back
- `server_info` - Get server information
- `user_count` - Get connected user count
- `list_commands` - List available commands

### Custom Handler Implementation

```go
type MyHandler struct{}

func (h *MyHandler) Handle(ctx context.Context, server *Server, sender string, params json.RawMessage) (interface{}, error) {
    // Your custom logic here
    return map[string]interface{}{
        "result": "success",
        "timestamp": time.Now().Unix(),
    }, nil
}

// Register the handler
server.RegisterServerHandler("my_command", &MyHandler{})
```

## 🐳 Docker Deployment

### Multi-Client Testing Setup

```yaml
# docker-compose.yml
version: '3.8'

services:
  websocket-server:
    build: ./websocket_server
    ports:
      - "443:443"
      - "80:80"
    environment:
      - JWT_SECRET=${JWT_SECRET}
      - MESSAGE_RATE_LIMIT=10
    volumes:
      - ./data:/app/data
    networks:
      - wsnet

  client-alice:
    build: ./client-sdk
    environment:
      - WS_USER_ID=alice
      - WS_USERNAME=Alice Smith
      - WS_PRIVATE_KEY=${ALICE_PRIVATE_KEY}
      - WS_SERVER_URL=https://websocket-server:443
      - INSECURE_TLS=true
    depends_on:
      - websocket-server
    networks:
      - wsnet

networks:
  wsnet:
    driver: bridge
```

### Environment Setup

```bash
# Generate keys for clients
./scripts/generate-keys.sh

# Start all services
docker compose up -d

# View logs
docker compose logs -f

# Attach to client
docker attach ws-client-alice
```

## 📊 Monitoring & Analytics

The server tracks:
- **Session Metrics**: Duration, connection/disconnection times
- **Message Analytics**: Volume, delivery rates, encryption usage
- **User Engagement**: Daily/weekly active users
- **Performance Metrics**: Response times, error rates

Access analytics via:
```http
GET /analytics/summary
GET /analytics/users/daily
GET /analytics/messages/stats
```

## 🔧 Development

### Running Tests

```bash
# Run all tests
go test ./...

# Run with coverage
go test -cover ./...

# Run benchmarks
go test -bench=. ./...
```

### Project Structure

```
websocket_server/
├── main.go              # Server entry point
├── auth/               # Authentication logic
│   ├── auth.go        # Ed25519 & JWT handling
│   └── handlers.go    # HTTP auth endpoints
├── ws/                # WebSocket handling
│   ├── server.go      # Core WebSocket server
│   ├── client.go      # Client connection management
│   └── handlers.go    # Message routing
├── models/            # Database models
│   ├── user.go       # User model
│   └── message.go    # Message model
├── crypto/            # Encryption utilities
│   └── crypto.go     # X25519 & AES functions
└── utils/            # Helper functions
```

## 🚨 Security Considerations

### Production Checklist

- [ ] Use valid TLS certificates (not self-signed)
- [ ] Set strong `JWT_SECRET` (minimum 32 characters)
- [ ] Configure `ALLOWED_ORIGINS` to restrict connections
- [ ] Enable security logging with `SECURITY_LOG_FILE`
- [ ] Implement rate limiting appropriate for your load
- [ ] Regular security audits of dependencies
- [ ] Monitor for unusual activity patterns
- [ ] Implement IP-based blocking for abusive clients
- [ ] Regular key rotation schedule
- [ ] Database backups and encryption at rest

### Best Practices

1. **Never log private keys or sensitive data**
2. **Always validate and sanitize input**
3. **Use prepared statements for database queries**
4. **Implement proper error handling without exposing internals**
5. **Regular security updates and dependency scanning**

## 📝 License

MIT License - See LICENSE file for details

## 🤝 Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Write tests for new features
4. Ensure all tests pass
5. Submit a pull request

## 📚 Additional Resources

- [Message Format Specification](./MESSAGE_FORMAT.md)
- [API Documentation](./docs/api.md)
- [Security Audit](./docs/security.md)
- [Performance Tuning](./docs/performance.md)

## 💡 Support

For issues, questions, or contributions:
- Open an issue on GitHub
- Check existing documentation
- Review closed issues for solutions

---

Built with ❤️ using Go, SQLite, and WebSockets