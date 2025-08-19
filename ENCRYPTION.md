# End-to-End Encryption Implementation

## Overview
This system implements end-to-end encryption for direct messages using a hybrid encryption approach combining AES-256-GCM (symmetric) for content encryption and X25519 (asymmetric) for key exchange.

## Architecture

### Encryption Flow
1. **Key Generation**: Each client generates or derives X25519 key pairs for encryption
2. **Message Encryption**: 
   - Generate a random AES-256 key for each message
   - Encrypt message content with AES-256-GCM
   - Encrypt the AES key with recipient's X25519 public key
3. **Message Transmission**: Server relays encrypted content without ability to decrypt
4. **Message Decryption**: Recipient uses their X25519 private key to decrypt AES key, then decrypts content

### Key Components

#### Client SDK (`client-sdk/`)
- **crypto/crypto.go**: Core cryptographic functions
  - `GenerateX25519KeyPair()`: Generate new X25519 keys
  - `DeriveX25519FromEd25519Seed()`: Derive X25519 keys from Ed25519 signing keys
  - `EncryptSymmetricKey()`: Encrypt AES key with X25519
  - `DecryptSymmetricKey()`: Decrypt AES key with X25519
  - `EncryptAESGCM()`: Encrypt content with AES-256-GCM
  - `DecryptAESGCM()`: Decrypt content with AES-256-GCM

- **auth/auth.go**: Key management
  - Generates/derives X25519 keys during initialization
  - Sends X25519 public key during registration
  - Fetches recipient public keys for encryption

- **client.go**: Transparent encryption/decryption
  - `encryptMessage()`: Automatically encrypts direct messages
  - `decryptMessage()`: Automatically decrypts received messages
  - Controlled by `EncryptionPolicy` setting

#### Server (`websocket_server/`)
- **auth/auth.go**: Stores X25519 public keys in database
- **models/user.go**: User model includes `x25519_public_key` field
- Server acts as blind relay - cannot decrypt messages

## Usage

### Basic Setup
```go
config := &client.Config{
    ServerURL:        "https://localhost:443",
    UserID:           "alice",
    Username:         "Alice",
    EncryptionPolicy: client.EncryptionRequired, // or EncryptionPreferred
}

client, _ := client.NewClient(config)
```

### Sending Encrypted Messages
```go
// Direct messages are automatically encrypted
err := client.SendMessage("bob", "Secret message", false)

// Broadcasts are never encrypted
err := client.Broadcast("Public announcement")
```

### Encryption Policies
- `EncryptionDisabled`: Never encrypt messages
- `EncryptionPreferred`: Try to encrypt, fall back to plaintext if encryption fails
- `EncryptionRequired`: Always encrypt, fail if encryption is not possible

## Security Properties

### What's Protected
- ✅ Message content is end-to-end encrypted
- ✅ Server cannot read direct messages
- ✅ Each message uses a unique AES key
- ✅ Forward secrecy through ephemeral keys in box seal

### What's Not Protected
- ❌ Metadata (sender, recipient, timestamp) is visible to server
- ❌ Broadcast messages are intentionally unencrypted
- ❌ User presence/online status is visible

## Database Schema

### Users Table
```sql
CREATE TABLE users (
    user_id TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    public_key TEXT NOT NULL,        -- Ed25519 signing key
    x25519_public_key TEXT,          -- X25519 encryption key
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## Testing

Run the encryption test:
```bash
go test ./crypto -v
go test ./auth -v
```

## Implementation Details

### Message Format
Encrypted messages include:
- `header.encrypted_key`: Base64-encoded encrypted AES key
- `header.encryption_nonce`: Base64-encoded nonce for AES-GCM
- `body.content`: Base64-encoded encrypted content

### Key Derivation
X25519 keys can be:
1. Generated independently using `GenerateX25519KeyPair()`
2. Derived from Ed25519 keys using `DeriveX25519FromEd25519Seed()`

The derivation approach ensures consistent encryption keys across sessions when using the same Ed25519 identity.

## Limitations
- No group encryption support (only 1-to-1 messages)
- No message history encryption (only real-time messages)
- No perfect forward secrecy between messages (uses static X25519 keys)