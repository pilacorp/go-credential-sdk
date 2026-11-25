package didcomm

import (
	"fmt"

	"github.com/pilacorp/go-credential-sdk/didcomm/crypto"
	"github.com/pilacorp/go-credential-sdk/didcomm/jwe"
)

// Encrypt encrypts plaintext for the other holder of key and returns a
// flattened JWE JSON serialization (RFC 7516 §7.2.2) with the protected
// header {"alg":"dir","enc":"A256GCM"}. key is the content encryption key
// (RFC 7518 §4.5) and must be the 32 bytes GetFromKeys returns. The encoded
// protected header is authenticated as AAD (RFC 7516 §5.1 step 14).
func Encrypt(key []byte, plaintext string) (string, error) {
	if len(key) != keySize {
		return "", fmt.Errorf("invalid key size: got %d bytes, want %d for %s", len(key), keySize, jwe.Encryption)
	}

	nonce, ciphertext, tag, err := crypto.EncryptAESGCM(key, []byte(plaintext), []byte(jwe.ProtectedHeader))
	if err != nil {
		return "", fmt.Errorf("encrypt: %w", err)
	}

	return jwe.BuildJWE(jwe.ProtectedHeader, nonce, ciphertext, tag)
}
