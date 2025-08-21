package client

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"github.com/IonesioJunior/Synaptic/client-sdk/auth"
	"github.com/IonesioJunior/Synaptic/client-sdk/crypto"
	"github.com/IonesioJunior/Synaptic/client-sdk/types"
)

const (
	writeWait         = 10 * time.Second
	pongWait          = 60 * time.Second
	pingPeriod        = (pongWait * 9) / 10
	maxMessageSize    = 1024 * 1024
	reconnectDelay    = 5 * time.Second
	maxReconnectDelay = 2 * time.Minute
)

// EncryptionPolicy defines how the client handles message encryption
type EncryptionPolicy int

const (
	// EncryptionDisabled - Never encrypt messages
	EncryptionDisabled EncryptionPolicy = iota
	// EncryptionPreferred - Try to encrypt, fall back to plaintext if encryption fails
	EncryptionPreferred
	// EncryptionRequired - Always encrypt, fail if encryption is not possible
	EncryptionRequired
)

type Config struct {
	ServerURL         string
	UserID            string
	Username          string
	PrivateKey        string
	AutoReconnect     bool
	MaxReconnectWait  time.Duration
	MessageBufferSize int
	Workers           int
	Debug             bool
	InsecureTLS       bool             // Skip TLS verification for development/testing
	EncryptionPolicy  EncryptionPolicy // How to handle message encryption
}

type Client struct {
	config *Config
	auth   *auth.AuthManager
	conn   *websocket.Conn
	state  atomic.Int32

	sendChan    chan *types.Message
	receiveChan chan *types.Message
	errorChan   chan error

	messageHandlers []types.MessageHandler
	handlersLock    sync.RWMutex

	reconnectTimer *time.Timer
	reconnectDelay time.Duration

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	connLock sync.RWMutex

	onConnect    func()
	onDisconnect func(error)
	onReconnect  func(attempt int)

	logger    *log.Logger
	userCache sync.Map

	workerPool chan struct{}
	metrics    *ClientMetrics
}

type ClientMetrics struct {
	messagesSent     atomic.Uint64
	messagesReceived atomic.Uint64
	reconnectCount   atomic.Uint32
	errorsCount      atomic.Uint32
}

func NewClient(config *Config) (*Client, error) {
	if config.ServerURL == "" {
		return nil, errors.New("server URL is required")
	}

	if config.MessageBufferSize <= 0 {
		config.MessageBufferSize = 256
	}

	if config.Workers <= 0 {
		config.Workers = 10
	}

	if config.MaxReconnectWait <= 0 {
		config.MaxReconnectWait = maxReconnectDelay
	}

	httpURL := config.ServerURL
	if httpURL[len(httpURL)-1] == '/' {
		httpURL = httpURL[:len(httpURL)-1]
	}

	var authManager *auth.AuthManager
	var err error

	if config.PrivateKey != "" {
		privKey, err := auth.LoadPrivateKeyFromBase64(config.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to load private key: %w", err)
		}
		authManager, err = auth.NewAuthManagerWithKeys(httpURL, config.UserID, config.Username, privKey)
		if err != nil {
			return nil, fmt.Errorf("failed to create auth manager: %w", err)
		}
	} else {
		authManager, err = auth.NewAuthManager(httpURL, config.UserID, config.Username)
		if err != nil {
			return nil, fmt.Errorf("failed to create auth manager: %w", err)
		}
	}

	// Set insecure TLS if configured (for development/testing)
	if config.InsecureTLS {
		authManager.SetInsecureTLS(true)
	}

	ctx, cancel := context.WithCancel(context.Background())

	client := &Client{
		config:         config,
		auth:           authManager,
		sendChan:       make(chan *types.Message, config.MessageBufferSize),
		receiveChan:    make(chan *types.Message, config.MessageBufferSize),
		errorChan:      make(chan error, 10),
		reconnectDelay: reconnectDelay,
		ctx:            ctx,
		cancel:         cancel,
		workerPool:     make(chan struct{}, config.Workers),
		metrics:        &ClientMetrics{},
	}

	if config.Debug {
		client.logger = log.New(log.Writer(), "[WS-Client] ", log.LstdFlags|log.Lshortfile)
	}

	for i := 0; i < config.Workers; i++ {
		client.workerPool <- struct{}{}
	}

	client.state.Store(int32(types.StateDisconnected))

	return client, nil
}

func (c *Client) Connect() error {
	if !c.compareAndSwapState(types.StateDisconnected, types.StateConnecting) &&
		!c.compareAndSwapState(types.StateReconnecting, types.StateConnecting) {
		return errors.New("already connected or connecting")
	}

	exists, err := c.auth.CheckUserExists()
	if err != nil {
		c.setState(types.StateDisconnected)
		return fmt.Errorf("failed to check user existence: %w", err)
	}

	if !exists {
		if err := c.auth.Register(); err != nil {
			c.setState(types.StateDisconnected)
			return fmt.Errorf("failed to register user: %w", err)
		}
		c.logDebug("User registered successfully")
	}

	if err := c.auth.Login(); err != nil {
		c.setState(types.StateDisconnected)
		return fmt.Errorf("failed to login: %w", err)
	}
	c.logDebug("Login successful")

	token, err := c.auth.GetToken()
	if err != nil {
		c.setState(types.StateDisconnected)
		return fmt.Errorf("failed to get token: %w", err)
	}

	wsURL := c.config.ServerURL
	if u, err := url.Parse(wsURL); err == nil {
		switch u.Scheme {
		case "http":
			u.Scheme = "ws"
		case "https":
			u.Scheme = "wss"
		}
		wsURL = u.String()
	}

	if wsURL[len(wsURL)-1] != '/' {
		wsURL += "/"
	}
	wsURL += "ws?token=" + token

	dialer := websocket.DefaultDialer
	if c.config.InsecureTLS {
		dialer.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
	}
	conn, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		c.setState(types.StateDisconnected)
		if c.config.AutoReconnect {
			c.scheduleReconnect()
		}
		return fmt.Errorf("failed to connect to WebSocket: %w", err)
	}

	c.connLock.Lock()
	c.conn = conn
	c.connLock.Unlock()

	c.setState(types.StateConnected)
	c.reconnectDelay = reconnectDelay

	c.wg.Add(2)
	go c.readPump()
	go c.writePump()

	if c.onConnect != nil {
		go c.onConnect()
	}

	c.logDebug("Connected to WebSocket server")

	return nil
}

func (c *Client) Disconnect() error {
	c.cancel()

	c.connLock.Lock()
	conn := c.conn
	c.connLock.Unlock()

	if conn != nil {
		conn.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
			time.Now().Add(writeWait))
		conn.Close()
	}

	c.setState(types.StateDisconnected)

	// Call disconnect callback
	if c.onDisconnect != nil {
		go c.onDisconnect(nil)
	}

	c.wg.Wait()

	return nil
}

func (c *Client) SendMessage(to, content string, sign bool) error {
	msg := &types.Message{
		Header: types.MessageHeader{
			From:      c.config.UserID,
			To:        to,
			Timestamp: time.Now(),
		},
		Body: types.MessageBody{
			Content: content,
		},
	}

	if to == "broadcast" {
		msg.Header.IsBroadcast = true
	} else if c.config.EncryptionPolicy != EncryptionDisabled {
		// All direct messages should be encrypted (not broadcasts)
		encrypted, err := c.encryptMessage(content, to)
		if err != nil {
			if c.config.EncryptionPolicy == EncryptionRequired {
				return fmt.Errorf("encryption failed: %w", err)
			}
			// Fall back to unencrypted if policy is Preferred
			c.logger.Printf("[WARN] Encryption failed, sending unencrypted: %v", err)
		} else {
			// Successfully encrypted
			msg.Body.Content = encrypted.EncryptedContent
			msg.Header.EncryptedKey = encrypted.EncryptedKey
			msg.Header.EncryptionNonce = encrypted.Nonce
		}
	}

	if sign && !msg.Header.IsBroadcast {
		msgBytes, err := json.Marshal(msg.Body.Content)
		if err != nil {
			return fmt.Errorf("failed to marshal message for signing: %w", err)
		}
		msg.Header.Signature = c.auth.SignMessage(msgBytes)
	}

	select {
	case c.sendChan <- msg:
		c.metrics.messagesSent.Add(1)
		return nil
	case <-c.ctx.Done():
		return errors.New("client is shutting down")
	case <-time.After(5 * time.Second):
		return errors.New("send timeout")
	}
}

func (c *Client) Broadcast(content string) error {
	return c.SendMessage("broadcast", content, false)
}

func (c *Client) AddMessageHandler(handler types.MessageHandler) {
	c.handlersLock.Lock()
	defer c.handlersLock.Unlock()
	c.messageHandlers = append(c.messageHandlers, handler)
}

func (c *Client) AddMessageHandlerFunc(handler func(*types.Message) error) {
	c.AddMessageHandler(types.MessageHandlerFunc(handler))
}

func (c *Client) OnConnect(fn func()) {
	c.onConnect = fn
}

func (c *Client) OnDisconnect(fn func(error)) {
	c.onDisconnect = fn
}

func (c *Client) OnReconnect(fn func(attempt int)) {
	c.onReconnect = fn
}

func (c *Client) GetReceiveChannel() <-chan *types.Message {
	return c.receiveChan
}

func (c *Client) GetErrorChannel() <-chan error {
	return c.errorChan
}

func (c *Client) GetState() types.ConnectionState {
	return types.ConnectionState(c.state.Load())
}

func (c *Client) IsConnected() bool {
	return c.GetState() == types.StateConnected
}

func (c *Client) GetMetrics() (sent, received uint64, reconnects, errors uint32) {
	return c.metrics.messagesSent.Load(),
		c.metrics.messagesReceived.Load(),
		c.metrics.reconnectCount.Load(),
		c.metrics.errorsCount.Load()
}

func (c *Client) GetUserInfo(userID string) (*types.User, error) {
	if cached, ok := c.userCache.Load(userID); ok {
		if user, ok := cached.(*types.User); ok {
			return user, nil
		}
	}

	user, err := c.auth.GetUserInfo(userID)
	if err != nil {
		return nil, err
	}

	c.userCache.Store(userID, user)
	return user, nil
}

func (c *Client) VerifyMessageSignature(msg *types.Message) (bool, error) {
	if msg.Header.Signature == "" {
		return false, nil
	}

	sender, err := c.GetUserInfo(msg.Header.From)
	if err != nil {
		return false, fmt.Errorf("failed to get sender info: %w", err)
	}

	msgBytes, err := json.Marshal(msg.Body.Content)
	if err != nil {
		return false, fmt.Errorf("failed to marshal message content: %w", err)
	}

	return c.auth.VerifySignature(sender.PublicKey, msg.Header.Signature, msgBytes), nil
}

// EncryptedMessage holds the encrypted message components
type EncryptedMessage struct {
	EncryptedContent string // Base64 encoded encrypted content
	EncryptedKey     string // Base64 encoded encrypted AES key
	Nonce            string // Base64 encoded nonce
}

// encryptMessage encrypts a message for a specific recipient
func (c *Client) encryptMessage(content, recipientID string) (*EncryptedMessage, error) {
	// Get recipient's X25519 public key
	recipientX25519Key, err := c.auth.GetUserPublicKeyX25519(recipientID)
	if err != nil {
		return nil, fmt.Errorf("failed to get recipient's public key: %w", err)
	}

	// Generate AES key for this message
	aesKey, err := crypto.GenerateAESKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate AES key: %w", err)
	}

	// Encrypt the message content with AES-GCM
	encryptedContent, nonce, err := crypto.EncryptAESGCM([]byte(content), aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt content: %w", err)
	}

	// Encrypt the AES key with recipient's X25519 public key
	encryptedKey, err := crypto.EncryptSymmetricKey(aesKey, recipientX25519Key)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt symmetric key: %w", err)
	}

	return &EncryptedMessage{
		EncryptedContent: crypto.EncodeBase64(encryptedContent),
		EncryptedKey:     crypto.EncodeBase64(encryptedKey),
		Nonce:            crypto.EncodeBase64(nonce),
	}, nil
}

// decryptMessage decrypts an encrypted message
func (c *Client) decryptMessage(msg *types.Message) (string, error) {
	// Message is encrypted if it has an encrypted key
	if msg.Header.EncryptedKey == "" {
		return msg.Body.Content, nil
	}

	// Check if auth manager is available
	if c.auth == nil {
		return "", fmt.Errorf("auth manager not initialized")
	}

	// Get our X25519 private key
	x25519PrivKey, err := c.auth.GetOwnX25519PrivateKey()
	if err != nil {
		return "", fmt.Errorf("failed to get X25519 private key: %w", err)
	}

	// Decode the encrypted AES key
	encryptedKey, err := crypto.DecodeBase64(msg.Header.EncryptedKey)
	if err != nil {
		return "", fmt.Errorf("failed to decode encrypted key: %w", err)
	}

	// Decrypt the AES key
	aesKey, err := crypto.DecryptSymmetricKey(encryptedKey, x25519PrivKey)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt symmetric key: %w", err)
	}

	// Decode the nonce
	nonce, err := crypto.DecodeBase64(msg.Header.EncryptionNonce)
	if err != nil {
		return "", fmt.Errorf("failed to decode nonce: %w", err)
	}

	// Decode the encrypted content
	encryptedContent, err := crypto.DecodeBase64(msg.Body.Content)
	if err != nil {
		return "", fmt.Errorf("failed to decode encrypted content: %w", err)
	}

	// Decrypt the content with AES-GCM
	decryptedContent, err := crypto.DecryptAESGCM(encryptedContent, aesKey, nonce)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt content: %w", err)
	}

	return string(decryptedContent), nil
}
