package auth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/genericwsserver/client-sdk/crypto"
	"github.com/genericwsserver/client-sdk/types"
)

type PublicKeyCache struct {
	Ed25519Key string
	X25519Key  []byte
	ExpiresAt  time.Time
}

type AuthManager struct {
	baseURL       string
	privateKey    ed25519.PrivateKey
	publicKey     ed25519.PublicKey
	x25519PrivKey []byte // X25519 private key for encryption
	x25519PubKey  []byte // X25519 public key for encryption
	userID        string
	username      string
	token         string
	tokenExp      time.Time
	mu            sync.RWMutex
	httpClient    *http.Client
	insecureTLS   bool
	keyCache      map[string]*PublicKeyCache
	keyCacheMu    sync.RWMutex
}

func NewAuthManager(baseURL, userID, username string) (*AuthManager, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Ed25519 keys: %w", err)
	}

	// Generate X25519 keys for encryption
	x25519Pub, x25519Priv, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate X25519 keys: %w", err)
	}

	am := &AuthManager{
		baseURL:       baseURL,
		privateKey:    priv,
		publicKey:     pub,
		x25519PrivKey: x25519Priv,
		x25519PubKey:  x25519Pub,
		userID:        userID,
		username:      username,
		keyCache:      make(map[string]*PublicKeyCache),
	}
	am.setupHTTPClient()
	return am, nil
}

func NewAuthManagerWithKeys(baseURL, userID, username string, privateKey ed25519.PrivateKey) (*AuthManager, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid private key size")
	}

	publicKeyInterface := privateKey.Public()
	publicKey, ok := publicKeyInterface.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("failed to get public key from private key")
	}

	// Derive X25519 keys from Ed25519 seed for consistent keys
	x25519Pub, x25519Priv, err := crypto.DeriveX25519FromEd25519Seed(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to derive X25519 keys: %w", err)
	}

	am := &AuthManager{
		baseURL:       baseURL,
		privateKey:    privateKey,
		publicKey:     publicKey,
		x25519PrivKey: x25519Priv,
		x25519PubKey:  x25519Pub,
		userID:        userID,
		username:      username,
		keyCache:      make(map[string]*PublicKeyCache),
	}
	am.setupHTTPClient()
	return am, nil
}

func (am *AuthManager) SetInsecureTLS(insecure bool) {
	am.insecureTLS = insecure
	am.setupHTTPClient()
}

func (am *AuthManager) setupHTTPClient() {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: am.insecureTLS,
		},
	}

	am.httpClient = &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}
}

func LoadPrivateKeyFromBase64(encoded string) (ed25519.PrivateKey, error) {
	keyBytes, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %w", err)
	}

	if len(keyBytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size: got %d, want %d", len(keyBytes), ed25519.PrivateKeySize)
	}

	return ed25519.PrivateKey(keyBytes), nil
}

func (am *AuthManager) GetPublicKeyBase64() string {
	return base64.StdEncoding.EncodeToString(am.publicKey)
}

func (am *AuthManager) GetX25519PublicKeyBase64() string {
	return base64.StdEncoding.EncodeToString(am.x25519PubKey)
}

func (am *AuthManager) GetPrivateKeyBase64() string {
	return base64.StdEncoding.EncodeToString(am.privateKey)
}

func (am *AuthManager) CheckUserExists() (bool, error) {
	url := fmt.Sprintf("%s/auth/check-userid/%s", am.baseURL, am.userID)

	resp, err := am.httpClient.Get(url)
	if err != nil {
		return false, fmt.Errorf("failed to check user existence: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return false, fmt.Errorf("server error: %s", body)
	}

	var result types.UserExistsResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, fmt.Errorf("failed to decode response: %w", err)
	}

	return result.Exists, nil
}

func (am *AuthManager) Register() error {
	url := fmt.Sprintf("%s/auth/register", am.baseURL)

	req := types.RegistrationRequest{
		UserID:          am.userID,
		Username:        am.username,
		PublicKey:       am.GetPublicKeyBase64(),
		X25519PublicKey: am.GetX25519PublicKeyBase64(),
	}

	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal registration request: %w", err)
	}

	resp, err := am.httpClient.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to register: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("registration failed: %s", respBody)
	}

	return nil
}

func (am *AuthManager) Login() error {
	challenge, err := am.requestChallenge()
	if err != nil {
		return fmt.Errorf("failed to get challenge: %w", err)
	}

	token, err := am.verifyChallenge(challenge)
	if err != nil {
		return fmt.Errorf("failed to verify challenge: %w", err)
	}

	am.mu.Lock()
	am.token = token
	am.tokenExp = time.Now().Add(23 * time.Hour)
	am.mu.Unlock()

	return nil
}

func (am *AuthManager) requestChallenge() (string, error) {
	url := fmt.Sprintf("%s/auth/login", am.baseURL)

	req := types.LoginRequest{
		UserID: am.userID,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("failed to marshal login request: %w", err)
	}

	resp, err := am.httpClient.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("failed to request challenge: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("challenge request failed: %s", respBody)
	}

	var challengeResp types.ChallengeResponse
	if err := json.NewDecoder(resp.Body).Decode(&challengeResp); err != nil {
		return "", fmt.Errorf("failed to decode challenge response: %w", err)
	}

	return challengeResp.Challenge, nil
}

func (am *AuthManager) verifyChallenge(challenge string) (string, error) {
	challengeBytes, err := base64.StdEncoding.DecodeString(challenge)
	if err != nil {
		return "", fmt.Errorf("failed to decode challenge: %w", err)
	}

	signature := ed25519.Sign(am.privateKey, challengeBytes)
	signatureBase64 := base64.StdEncoding.EncodeToString(signature)

	url := fmt.Sprintf("%s/auth/login?verify=true", am.baseURL)

	req := types.LoginVerifyRequest{
		UserID:    am.userID,
		Signature: signatureBase64,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("failed to marshal verify request: %w", err)
	}

	resp, err := am.httpClient.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("failed to verify challenge: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("challenge verification failed: %s", respBody)
	}

	var tokenResp types.TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("failed to decode token response: %w", err)
	}

	return tokenResp.Token, nil
}

func (am *AuthManager) GetToken() (string, error) {
	am.mu.RLock()
	token := am.token
	exp := am.tokenExp
	am.mu.RUnlock()

	if token == "" {
		return "", errors.New("not authenticated")
	}

	if time.Now().After(exp) {
		if err := am.Login(); err != nil {
			return "", fmt.Errorf("token expired and re-login failed: %w", err)
		}
		am.mu.RLock()
		token = am.token
		am.mu.RUnlock()
	}

	return token, nil
}

func (am *AuthManager) IsTokenValid() bool {
	am.mu.RLock()
	defer am.mu.RUnlock()

	if am.token == "" {
		return false
	}

	return time.Now().Before(am.tokenExp)
}

func (am *AuthManager) SignMessage(message []byte) string {
	signature := ed25519.Sign(am.privateKey, message)
	return base64.StdEncoding.EncodeToString(signature)
}

func (am *AuthManager) VerifySignature(publicKeyBase64, signatureBase64 string, message []byte) bool {
	publicKey, err := base64.StdEncoding.DecodeString(publicKeyBase64)
	if err != nil {
		return false
	}

	signature, err := base64.StdEncoding.DecodeString(signatureBase64)
	if err != nil {
		return false
	}

	return ed25519.Verify(publicKey, message, signature)
}

func (am *AuthManager) GetUserInfo(userID string) (*types.User, error) {
	url := fmt.Sprintf("%s/auth/users/%s", am.baseURL, userID)

	resp, err := am.httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("user not found: %s", userID)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server error: %s", body)
	}

	var user types.User
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}

	return &user, nil
}

func (am *AuthManager) GetUserID() string {
	return am.userID
}

// GetUserPublicKeyX25519 fetches a user's X25519 public key for encryption
func (am *AuthManager) GetUserPublicKeyX25519(userID string) ([]byte, error) {
	// IMPORTANT: For this demo to work, both sender and receiver must derive
	// their X25519 keys from their Ed25519 keys in the same way

	// If it's our own user ID, return our own X25519 public key
	if userID == am.userID {
		return am.x25519PubKey, nil
	}

	// Check cache first
	am.keyCacheMu.RLock()
	if cached, exists := am.keyCache[userID]; exists && cached.ExpiresAt.After(time.Now()) {
		am.keyCacheMu.RUnlock()
		return cached.X25519Key, nil
	}
	am.keyCacheMu.RUnlock()

	// Fetch user info from server
	user, err := am.GetUserInfo(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}

	// Use the X25519 public key from the server if available
	var x25519PubKey []byte
	if user.X25519PublicKey != "" {
		x25519PubKey, err = base64.StdEncoding.DecodeString(user.X25519PublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decode X25519 public key: %w", err)
		}
	} else {
		// Fallback: derive from user ID (for backward compatibility)
		// This won't work for actual encryption but prevents errors
		h := sha256.New()
		h.Write([]byte("X25519-FALLBACK:"))
		h.Write([]byte(userID))
		x25519PubKey = h.Sum(nil)[:32]
	}

	// Cache the result
	am.keyCacheMu.Lock()
	am.keyCache[userID] = &PublicKeyCache{
		Ed25519Key: user.PublicKey,
		X25519Key:  x25519PubKey,
		ExpiresAt:  time.Now().Add(1 * time.Hour),
	}
	am.keyCacheMu.Unlock()

	return x25519PubKey, nil
}

// GetOwnX25519PrivateKey returns own X25519 private key for decryption
func (am *AuthManager) GetOwnX25519PrivateKey() ([]byte, error) {
	if am.x25519PrivKey == nil {
		return nil, fmt.Errorf("X25519 private key not initialized")
	}
	return am.x25519PrivKey, nil
}

// ClearKeyCache clears the public key cache
func (am *AuthManager) ClearKeyCache() {
	am.keyCacheMu.Lock()
	am.keyCache = make(map[string]*PublicKeyCache)
	am.keyCacheMu.Unlock()
}

func ParseJWTClaims(tokenString string) (jwt.MapClaims, error) {
	parser := jwt.NewParser()
	token, _, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid token claims")
	}

	return claims, nil
}
