# WebSocket Server Architecture

## Table of Contents
- [Overview](#overview)
- [System Architecture](#system-architecture)
- [Component Architecture](#component-architecture)
- [Data Flow](#data-flow)
- [Security Architecture](#security-architecture)
- [Database Schema](#database-schema)
- [Message Processing Pipeline](#message-processing-pipeline)
- [Authentication Flow](#authentication-flow)
- [Deployment Architecture](#deployment-architecture)

## Overview

The WebSocket Server is a high-performance, secure real-time communication platform built in Go. It provides end-to-end encryption, authentication, rate limiting, and comprehensive message handling capabilities.

## System Architecture

```mermaid
graph TB
    subgraph "Client Layer"
        C1[Client 1<br/>Alice]
        C2[Client 2<br/>Bob]
        C3[Client N<br/>...]
    end

    subgraph "Network Layer"
        LB[Load Balancer<br/>HTTPS/WSS]
        HTTP[HTTP Server<br/>:80]
        HTTPS[HTTPS Server<br/>:443]
    end

    subgraph "WebSocket Server Core"
        MUX[HTTP Multiplexer<br/>gorilla/mux]
        WS[WebSocket Handler<br/>gorilla/websocket]
        AUTH[Auth Service<br/>JWT + Ed25519]
        RL[Rate Limiter<br/>Token Bucket]
        SH[Server Handlers<br/>Command Registry]
    end

    subgraph "Data Layer"
        DB[(SQLite Database<br/>WAL Mode)]
        CACHE[User Cache<br/>sync.Map]
        METRICS[Metrics Store<br/>In-Memory]
    end

    C1 -->|TLS/WSS| LB
    C2 -->|TLS/WSS| LB
    C3 -->|TLS/WSS| LB
    
    LB --> HTTPS
    HTTP -->|Redirect| HTTPS
    HTTPS --> MUX
    
    MUX --> WS
    MUX --> AUTH
    
    WS --> RL
    WS --> SH
    WS --> CACHE
    
    AUTH --> DB
    SH --> DB
    WS --> DB
    
    WS --> METRICS
    METRICS -.->|Persist| DB
```

## Component Architecture

### Core Components Dependency Graph

```mermaid
graph LR
    subgraph "Entry Point"
        MAIN[main.go]
    end

    subgraph "Configuration"
        CONFIG[config<br/>- LoadConfig<br/>- Environment Vars]
    end

    subgraph "Database Layer"
        DB[db<br/>- Initialize<br/>- RunMigrations<br/>- WAL Mode]
    end

    subgraph "Authentication"
        AUTH[auth<br/>- Service<br/>- JWT Handler<br/>- Ed25519 Crypto]
        MW[middleware<br/>- CORS<br/>- Auth Validation]
        LOG[logging<br/>- Security Audit]
    end

    subgraph "WebSocket Core"
        SERVER[ws/server<br/>- Connection Manager<br/>- Client Registry]
        CLIENT[ws/client<br/>- Read/Write Pumps<br/>- Message Queue]
        HANDLERS[ws/handlers<br/>- Message Router<br/>- Type Handlers]
        MSG[ws/message<br/>- Server Commands<br/>- Signatures]
        RATE[ws/ratelimit<br/>- Token Bucket<br/>- Per-User Limits]
    end

    subgraph "HTTP Handlers"
        ROUTER[handlers/router<br/>- Route Setup<br/>- Static Files]
    end

    subgraph "Models"
        MODELS[models<br/>- User<br/>- Message<br/>- ServerCommand]
    end

    subgraph "Metrics"
        METRICS[metrics<br/>- Session Tracking<br/>- Message Stats<br/>- Analytics]
    end

    MAIN --> CONFIG
    MAIN --> DB
    MAIN --> AUTH
    MAIN --> SERVER
    MAIN --> ROUTER
    
    CONFIG --> DB
    CONFIG --> AUTH
    CONFIG --> SERVER
    
    AUTH --> DB
    AUTH --> MW
    AUTH --> LOG
    
    SERVER --> CLIENT
    SERVER --> HANDLERS
    SERVER --> MSG
    SERVER --> RATE
    SERVER --> DB
    SERVER --> AUTH
    
    HANDLERS --> MSG
    MSG --> MODELS
    
    CLIENT --> MODELS
    
    ROUTER --> SERVER
    ROUTER --> AUTH
    
    METRICS --> DB
    SERVER --> METRICS
```

### Detailed Component Interactions

```mermaid
sequenceDiagram
    participant C as Client
    participant H as HTTPS Server
    participant A as Auth Service
    participant W as WebSocket Server
    participant D as Database
    participant M as Metrics

    Note over C,M: Connection & Authentication Flow
    
    C->>H: POST /auth/register
    H->>A: HandleRegistration()
    A->>D: Store User + Keys
    D-->>A: Success
    A-->>C: Registration Complete

    C->>H: POST /auth/login
    H->>A: HandleLogin()
    A->>D: Get User
    A-->>C: Challenge

    C->>H: POST /auth/login?verify=true
    H->>A: Verify Signature
    A->>D: Update Session
    A-->>C: JWT Token

    Note over C,M: WebSocket Connection

    C->>H: GET /ws?token=JWT
    H->>W: HandleWebSocket()
    W->>A: VerifyToken()
    A-->>W: Valid User
    W->>W: Create Client
    W->>M: Track Connection
    W-->>C: WebSocket Established

    Note over C,M: Message Processing

    loop Message Exchange
        C->>W: Send Message
        W->>W: Rate Limit Check
        W->>W: Process Message Type
        alt Direct Message
            W->>D: Store Message
            W->>W: Route to Recipient
        else Broadcast
            W->>W: Send to All Clients
        else Server Command
            W->>W: Execute Handler
            W->>D: Log Command
        end
        W->>M: Update Metrics
        W-->>C: Delivery Confirmation
    end
```

## Data Flow

### Message Processing Pipeline

```mermaid
flowchart TB
    subgraph "Input Stage"
        MSG[Incoming Message]
        PARSE[Parse JSON]
        VALIDATE[Validate Structure]
    end

    subgraph "Authentication Stage"
        SIG[Verify Signature<br/>if present]
        TOKEN[Validate Sender]
    end

    subgraph "Rate Limiting"
        BUCKET[Check Token Bucket]
        ALLOW{Allowed?}
        REJECT[Reject Message]
    end

    subgraph "Type Resolution"
        TYPE{Message Type?}
        DIRECT[Direct Message]
        BROAD[Broadcast]
        SERVER[Server Command]
    end

    subgraph "Processing"
        ENCRYPT[Check Encryption]
        STORE[Store in DB]
        ROUTE[Route to Recipients]
        EXEC[Execute Command]
    end

    subgraph "Delivery"
        QUEUE[Add to Send Queue]
        SEND[WebSocket Write]
        ACK[Acknowledge]
    end

    MSG --> PARSE
    PARSE --> VALIDATE
    VALIDATE --> SIG
    SIG --> TOKEN
    TOKEN --> BUCKET
    BUCKET --> ALLOW
    ALLOW -->|No| REJECT
    ALLOW -->|Yes| TYPE
    
    TYPE -->|direct| DIRECT
    TYPE -->|broadcast| BROAD
    TYPE -->|server| SERVER
    
    DIRECT --> ENCRYPT
    ENCRYPT --> STORE
    STORE --> ROUTE
    
    BROAD --> ROUTE
    
    SERVER --> EXEC
    EXEC --> STORE
    
    ROUTE --> QUEUE
    QUEUE --> SEND
    SEND --> ACK
```

## Security Architecture

### Cryptographic Components

```mermaid
graph TB
    subgraph "Key Management"
        ED[Ed25519 Keys<br/>Signing]
        X25[X25519 Keys<br/>Encryption]
        JWT[JWT Tokens<br/>Session]
    end

    subgraph "Authentication Flow"
        REG[Registration<br/>Store Public Keys]
        CHAL[Challenge-Response<br/>Prevent Replay]
        VERIFY[Signature Verification<br/>Ed25519]
    end

    subgraph "Encryption Pipeline"
        GEN[Generate AES Key<br/>256-bit]
        ENC[Encrypt Message<br/>AES-256-GCM]
        WRAP[Wrap AES Key<br/>X25519]
        SEND[Send Encrypted]
    end

    subgraph "Security Controls"
        RATE[Rate Limiting<br/>Token Bucket]
        CORS[CORS Validation<br/>Origin Check]
        TLS[TLS/SSL<br/>Transport Security]
        AUDIT[Audit Logging<br/>Security Events]
    end

    ED --> REG
    ED --> CHAL
    ED --> VERIFY
    
    X25 --> WRAP
    
    JWT --> CHAL
    
    GEN --> ENC
    ENC --> WRAP
    WRAP --> SEND
    
    VERIFY --> RATE
    RATE --> CORS
    CORS --> TLS
    TLS --> AUDIT
```

### Zero-Knowledge Architecture

```mermaid
flowchart LR
    subgraph "Client A"
        A1[Generate AES Key]
        A2[Encrypt Message]
        A3[Encrypt AES Key<br/>with B's Public Key]
    end

    subgraph "Server"
        S1[Receive Encrypted]
        S2[Cannot Decrypt<br/>No Private Keys]
        S3[Route to Client B]
        S4[Store Encrypted]
    end

    subgraph "Client B"
        B1[Decrypt AES Key<br/>with Private Key]
        B2[Decrypt Message<br/>with AES Key]
        B3[Read Plaintext]
    end

    A1 --> A2
    A2 --> A3
    A3 --> S1
    S1 --> S2
    S2 --> S3
    S3 --> S4
    S3 --> B1
    B1 --> B2
    B2 --> B3
```

## Database Schema

```mermaid
erDiagram
    USERS {
        TEXT user_id PK
        TEXT username
        TEXT public_key
        TEXT x25519_public_key
        TIMESTAMP created_at
    }

    MESSAGES {
        INTEGER id PK
        TEXT from_user FK
        TEXT to_user FK
        TEXT content
        TEXT encrypted_key
        TEXT encryption_nonce
        TIMESTAMP timestamp
        TEXT status
        TEXT signature
    }

    SESSIONS {
        INTEGER id PK
        TEXT user_id FK
        TIMESTAMP connected_at
        TIMESTAMP disconnected_at
        INTEGER messages_sent
        INTEGER messages_received
        TEXT ip_address
        TEXT user_agent
    }

    METRICS {
        INTEGER id PK
        TEXT metric_type
        TEXT metric_name
        REAL value
        TIMESTAMP timestamp
        TEXT metadata
    }

    USERS ||--o{ MESSAGES : sends
    USERS ||--o{ MESSAGES : receives
    USERS ||--o{ SESSIONS : has
    SESSIONS ||--o{ METRICS : generates
```

## Message Processing Pipeline

### Server Message Handler Architecture

```mermaid
classDiagram
    class ServerMessageHandler {
        <<interface>>
        +Handle(ctx, server, sender, params) (response, error)
    }

    class ServerMessageRegistry {
        -handlers map[string]ServerMessageHandler
        -mu sync.RWMutex
        +Register(command, handler) error
        +Get(command) (handler, bool)
        +ListCommands() []string
    }

    class PingHandler {
        +Handle(ctx, server, sender, params) (response, error)
    }

    class EchoHandler {
        +Handle(ctx, server, sender, params) (response, error)
    }

    class ServerInfoHandler {
        +Handle(ctx, server, sender, params) (response, error)
    }

    class UserCountHandler {
        +Handle(ctx, server, sender, params) (response, error)
    }

    class ListCommandsHandler {
        +Handle(ctx, server, sender, params) (response, error)
    }

    ServerMessageHandler <|.. PingHandler
    ServerMessageHandler <|.. EchoHandler
    ServerMessageHandler <|.. ServerInfoHandler
    ServerMessageHandler <|.. UserCountHandler
    ServerMessageHandler <|.. ListCommandsHandler
    
    ServerMessageRegistry o-- ServerMessageHandler : contains
```

## Authentication Flow

### Challenge-Response Protocol

```mermaid
stateDiagram-v2
    [*] --> Disconnected
    
    Disconnected --> Registration : POST /auth/register
    Registration --> Registered : Store Keys
    
    Registered --> RequestChallenge : POST /auth/login
    RequestChallenge --> ChallengeIssued : Generate Challenge
    
    ChallengeIssued --> VerifySignature : POST /auth/login?verify=true
    VerifySignature --> Authenticated : Valid Signature
    VerifySignature --> Failed : Invalid Signature
    
    Authenticated --> TokenIssued : Generate JWT
    TokenIssued --> Connected : WebSocket Connect
    
    Connected --> Active : Message Exchange
    Active --> Connected : Process Messages
    
    Connected --> Disconnected : Close Connection
    Failed --> Disconnected : Retry
    
    Active --> RateLimited : Exceed Limit
    RateLimited --> Connected : Wait Period
```

## Deployment Architecture

### Docker Container Architecture

```mermaid
graph TB
    subgraph "Docker Network: wsnet"
        subgraph "WebSocket Server Container"
            WS[websocket-server:443]
            HTTP_REDIRECT[HTTP:80 → HTTPS:443]
            DB_SERVER[(SQLite)]
            CERTS_SERVER[TLS Certificates]
        end

        subgraph "Client Containers"
            subgraph "Alice Container"
                ALICE[client-alice]
                ALICE_KEYS[Ed25519 Keys]
            end
            
            subgraph "Bob Container"
                BOB[client-bob]
                BOB_KEYS[Ed25519 Keys]
            end
            
            subgraph "Charlie Container"
                CHARLIE[client-charlie]
                CHARLIE_KEYS[Ed25519 Keys]
            end
            
            subgraph "Bot Container"
                BOT[message-bot]
                BOT_KEYS[Ed25519 Keys]
                AUTO[Auto Mode]
            end
        end
    end

    subgraph "Host Volumes"
        DATA[./data]
        CERTS[./certs]
        ENV[.env file]
    end

    subgraph "External"
        BROWSER[Web Browser]
        API[API Clients]
    end

    BROWSER -->|HTTPS:443| WS
    API -->|WSS:443| WS
    
    ALICE -->|WSS| WS
    BOB -->|WSS| WS
    CHARLIE -->|WSS| WS
    BOT -->|WSS| WS
    
    DATA -.->|Mount| DB_SERVER
    CERTS -.->|Mount| CERTS_SERVER
    ENV -.->|Keys| ALICE_KEYS
    ENV -.->|Keys| BOB_KEYS
    ENV -.->|Keys| CHARLIE_KEYS
    ENV -.->|Keys| BOT_KEYS
```

### High Availability Architecture (Future)

```mermaid
graph TB
    subgraph "Load Balancing Layer"
        LB[HAProxy/Nginx<br/>Load Balancer]
    end

    subgraph "Application Cluster"
        WS1[WebSocket Server 1]
        WS2[WebSocket Server 2]
        WS3[WebSocket Server N]
    end

    subgraph "Shared State"
        REDIS[(Redis<br/>Session Store)]
        PG[(PostgreSQL<br/>Message Store)]
    end

    subgraph "Message Queue"
        KAFKA[Kafka/RabbitMQ<br/>Event Stream]
    end

    LB --> WS1
    LB --> WS2
    LB --> WS3
    
    WS1 --> REDIS
    WS2 --> REDIS
    WS3 --> REDIS
    
    WS1 --> PG
    WS2 --> PG
    WS3 --> PG
    
    WS1 --> KAFKA
    WS2 --> KAFKA
    WS3 --> KAFKA
    
    KAFKA --> WS1
    KAFKA --> WS2
    KAFKA --> WS3
```

## Performance Characteristics

### Concurrent Connection Handling

```mermaid
graph LR
    subgraph "Per Client Resources"
        CLIENT[Client Connection]
        GOROUTINES[3 Goroutines<br/>- Read Pump<br/>- Write Pump<br/>- Ping Handler]
        CHANNELS[Channels<br/>- Send Buffer: 256<br/>- Close Signal]
        MEMORY[Memory<br/>~10KB per client]
    end

    subgraph "Shared Resources"
        POOL[Worker Pool<br/>Message Processing]
        RATE_LIMIT[Rate Limiter<br/>Token Buckets]
        DB_POOL[DB Connection Pool]
    end

    CLIENT --> GOROUTINES
    GOROUTINES --> CHANNELS
    CHANNELS --> MEMORY
    
    GOROUTINES --> POOL
    GOROUTINES --> RATE_LIMIT
    POOL --> DB_POOL
```

### Message Processing Performance

```mermaid
flowchart LR
    subgraph "Input"
        MSG[Message<br/>~1KB]
    end

    subgraph "Processing Time"
        PARSE[Parse<br/>~10μs]
        AUTH[Auth Check<br/>~50μs]
        RATE[Rate Limit<br/>~5μs]
        ROUTE[Routing<br/>~20μs]
        STORE[DB Store<br/>~500μs]
    end

    subgraph "Output"
        DELIVERY[Total<br/>~600μs]
    end

    MSG --> PARSE
    PARSE --> AUTH
    AUTH --> RATE
    RATE --> ROUTE
    ROUTE --> STORE
    STORE --> DELIVERY
```

## Monitoring & Observability

### Metrics Collection Pipeline

```mermaid
graph TB
    subgraph "Event Sources"
        CONN[Connection Events]
        MSG[Message Events]
        ERR[Error Events]
        PERF[Performance Metrics]
    end

    subgraph "Metrics Aggregation"
        COLLECTOR[Metrics Collector]
        COUNTER[Counters<br/>- Messages<br/>- Connections]
        GAUGE[Gauges<br/>- Active Users<br/>- Queue Size]
        HISTOGRAM[Histograms<br/>- Response Time<br/>- Message Size]
    end

    subgraph "Storage & Export"
        MEMORY[In-Memory Store]
        PERSIST[SQLite Persistence]
        API[Metrics API<br/>/metrics]
    end

    CONN --> COLLECTOR
    MSG --> COLLECTOR
    ERR --> COLLECTOR
    PERF --> COLLECTOR
    
    COLLECTOR --> COUNTER
    COLLECTOR --> GAUGE
    COLLECTOR --> HISTOGRAM
    
    COUNTER --> MEMORY
    GAUGE --> MEMORY
    HISTOGRAM --> MEMORY
    
    MEMORY --> PERSIST
    MEMORY --> API
```

## Error Handling & Recovery

### Error Recovery Flow

```mermaid
stateDiagram-v2
    [*] --> Normal
    
    Normal --> Error : Exception Occurs
    
    Error --> Recoverable : Check Type
    Error --> Fatal : Unrecoverable
    
    Recoverable --> Retry : Attempt Recovery
    Retry --> Normal : Success
    Retry --> Backoff : Failure
    
    Backoff --> Retry : Wait Period
    Backoff --> Fatal : Max Retries
    
    Fatal --> Shutdown : Graceful Shutdown
    Shutdown --> [*]
    
    Normal --> Monitoring : Health Checks
    Monitoring --> Normal : Healthy
    Monitoring --> Error : Unhealthy
```

---

## Summary

The WebSocket Server architecture is designed for:

1. **Security First**: Zero-knowledge encryption, signature verification, and comprehensive authentication
2. **Scalability**: Concurrent connection handling with efficient resource usage
3. **Reliability**: Graceful error handling, automatic reconnection support, and message persistence
4. **Performance**: Optimized message routing, rate limiting, and minimal processing overhead
5. **Observability**: Comprehensive metrics, audit logging, and health monitoring
6. **Extensibility**: Plugin-based server commands, modular component design

The architecture supports thousands of concurrent connections while maintaining sub-millisecond message processing times and ensuring end-to-end encryption for sensitive communications.