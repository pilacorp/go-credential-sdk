package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// EncryptAESGCM seals plaintext with AES-GCM under key, authenticating aad
// too, and returns the random 96-bit nonce, the ciphertext and the 128-bit
// tag separately, as JWE carries them (RFC 7518 §5.3). The tag has its own
// backing array, so appending to the ciphertext cannot overwrite it.
func EncryptAESGCM(key, plaintext, aad []byte) (nonce, ciphertext, tag []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("aes new cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("aes new gcm: %w", err)
	}

	nonce = make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, nil, fmt.Errorf("generate nonce: %w", err)
	}

	// Seal appends the tag to the ciphertext.
	sealed := gcm.Seal(nil, nonce, plaintext, aad)
	split := len(sealed) - gcm.Overhead()

	tag = append([]byte(nil), sealed[split:]...)

	return nonce, sealed[:split:split], tag, nil
}
