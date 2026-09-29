package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
)

const keyByteLength = 32

func hashSHA256(parts ...string) []byte {
	h := sha256.New()
	for _, part := range parts {
		h.Write([]byte{0})
		h.Write([]byte(part))
	}
	return h.Sum(nil)
}

func hashString(parts ...string) string {
	return hex.EncodeToString(hashSHA256(parts...))
}

func constantTimeEqualHex(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func newRandomString(byteLength int) (string, error) {
	b := make([]byte, byteLength)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func encryptAESGCM(key []byte, plaintext string) ([]byte, error) {
	if len(key) != keyByteLength {
		return nil, fmt.Errorf("encryption key must be %d bytes", keyByteLength)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, []byte(plaintext), nil), nil
}

func decryptAESGCM(key []byte, encrypted []byte) (string, error) {
	if len(key) != keyByteLength {
		return "", fmt.Errorf("encryption key must be %d bytes", keyByteLength)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(encrypted) < gcm.NonceSize() {
		return "", fmt.Errorf("ciphertext is too short")
	}
	nonce, ciphertext := encrypted[:gcm.NonceSize()], encrypted[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt failed")
	}
	return string(plaintext), nil
}
