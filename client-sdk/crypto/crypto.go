package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

// GenerateAESKey generates a random 256-bit AES key
func GenerateAESKey() ([]byte, error) {
	key := make([]byte, 32) // 256 bits
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("failed to generate AES key: %w", err)
	}
	return key, nil
}

// GenerateNonce generates a random nonce for AES-GCM
func GenerateNonce() ([]byte, error) {
	nonce := make([]byte, 12) // GCM standard nonce size
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	return nonce, nil
}

// EncryptAESGCM encrypts data using AES-256-GCM
func EncryptAESGCM(plaintext, key []byte) (ciphertext, nonce []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce, err = GenerateNonce()
	if err != nil {
		return nil, nil, err
	}

	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}

// DecryptAESGCM decrypts data using AES-256-GCM
func DecryptAESGCM(ciphertext, key, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

// GenerateX25519KeyPair generates a new X25519 key pair for encryption
func GenerateX25519KeyPair() (publicKey, privateKey []byte, err error) {
	var pub, priv [32]byte
	pubPtr, privPtr, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	copy(pub[:], pubPtr[:])
	copy(priv[:], privPtr[:])
	return pub[:], priv[:], nil
}

// DeriveX25519FromEd25519Seed derives X25519 keys from Ed25519 seed
// This provides a deterministic way to get encryption keys from signing keys
func DeriveX25519FromEd25519Seed(edPriv ed25519.PrivateKey) (x25519Pub, x25519Priv []byte, err error) {
	if len(edPriv) != ed25519.PrivateKeySize {
		return nil, nil, fmt.Errorf("invalid Ed25519 private key size")
	}

	// Ed25519 private key is 64 bytes: 32-byte seed + 32-byte public key
	// Use the seed to derive X25519 keys deterministically
	seed := edPriv[:32]

	// Hash the seed with a different prefix for X25519
	h := sha256.New()
	h.Write([]byte("X25519-from-Ed25519:"))
	h.Write(seed)
	x25519Seed := h.Sum(nil)

	// Clamp the private key as per X25519 spec
	x25519Seed[0] &= 248
	x25519Seed[31] &= 127
	x25519Seed[31] |= 64

	// Compute public key using curve25519.ScalarBaseMult
	var privArray [32]byte
	copy(privArray[:], x25519Seed)

	pubArray, err := curve25519.X25519(privArray[:], curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}

	return pubArray, privArray[:], nil
}

// EncryptSymmetricKey encrypts an AES key using X25519 public key encryption
func EncryptSymmetricKey(symmetricKey, recipientX25519PublicKey []byte) ([]byte, error) {
	if len(recipientX25519PublicKey) != 32 {
		return nil, fmt.Errorf("invalid X25519 public key size")
	}

	// Generate ephemeral X25519 key pair for this encryption
	ephemeralPublicKey, ephemeralPrivateKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}

	// Prepare the recipient's public key
	var recipientKey [32]byte
	copy(recipientKey[:], recipientX25519PublicKey)

	// Encrypt the symmetric key using nacl/box
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Seal the symmetric key
	encrypted := box.Seal(nil, symmetricKey, &nonce, &recipientKey, ephemeralPrivateKey)

	// Combine ephemeral public key + nonce + encrypted key for transmission
	result := make([]byte, 32+24+len(encrypted))
	copy(result[0:32], ephemeralPublicKey[:])
	copy(result[32:56], nonce[:])
	copy(result[56:], encrypted)

	return result, nil
}

// DecryptSymmetricKey decrypts an AES key using X25519 private key
func DecryptSymmetricKey(encryptedData, recipientX25519PrivateKey []byte) ([]byte, error) {
	if len(encryptedData) < 56 {
		return nil, fmt.Errorf("encrypted data too short: got %d bytes, need at least 56", len(encryptedData))
	}
	if len(recipientX25519PrivateKey) != 32 {
		return nil, fmt.Errorf("invalid X25519 private key size: got %d bytes, need 32", len(recipientX25519PrivateKey))
	}

	// Extract components
	var ephemeralPublicKey [32]byte
	var nonce [24]byte
	copy(ephemeralPublicKey[:], encryptedData[0:32])
	copy(nonce[:], encryptedData[32:56])
	encrypted := encryptedData[56:]

	// Prepare the private key
	var privateKey [32]byte
	copy(privateKey[:], recipientX25519PrivateKey)

	// Decrypt using nacl/box
	decrypted, ok := box.Open(nil, encrypted, &nonce, &ephemeralPublicKey, &privateKey)
	if !ok {
		return nil, fmt.Errorf("box.Open failed - could not decrypt (data len: %d)", len(encrypted))
	}

	return decrypted, nil
}

// EncodeBase64 encodes bytes to base64 string
func EncodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// DecodeBase64 decodes base64 string to bytes
func DecodeBase64(data string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(data)
}
