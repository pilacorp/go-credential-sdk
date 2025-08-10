package crypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto"
	"strings"
)

func VerifyJwtProof(req map[string]interface{}, publicKeyHex string) (bool, error) {
	jwtToken, ok := req["proof"].(map[string]interface{})["jwt"].(string)
	if jwtToken == "" || !ok {
		return false, fmt.Errorf("JWT token is missing")
	}

	signature, message, err := getSignatureAndMessage(jwtToken)
	if err != nil {
		return false, fmt.Errorf("failed to extract signature and message from JWT: %w", err)
	}

	pubBytes, err := keyToBytes(publicKeyHex)
	if err != nil {
		return false, fmt.Errorf("failed to convert public key to bytes: %w", err)
	}

	verified := verifySignature(pubBytes, message, signature)

	return verified, nil
}

// KeyToBytes converts a hex string with prefix 0x to a byte array.
func keyToBytes(key string) ([]byte, error) {
	if !strings.HasPrefix(key, "0x") {
		return nil, errors.New("key is not in hex format")
	}

	return hex.DecodeString(key[2:])
}

func getSignatureAndMessage(jwtToken string) ([]byte, []byte, error) {
	parts := strings.Split(jwtToken, ".")
	if len(parts) != 3 {
		return nil, nil, fmt.Errorf("invalid JWT format")
	}

	headerB64, payloadB64, signatureB64 := parts[0], parts[1], parts[2]

	signature, err := base64.RawURLEncoding.DecodeString(signatureB64)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode signature: %w", err)
	}

	message := []byte(headerB64 + "." + payloadB64)

	return signature, message, nil
}

// verifySignature verifies a signature of type secp256k1
// The length of the public key is 33 bytes
// The length of the message is positive
// The length of the signature should be 65 bytes (64 bytes + 1 recovery byte).
func verifySignature(publicKey, message, signature []byte) bool {
	if len(signature) != 65 || len(publicKey) != 33 || len(message) == 0 {
		return verifySignatureWithoutV(publicKey, message, signature)
	}

	// Create hash of the message (same as in SignMessage)
	hash := sha256.Sum256(message)

	// Recover the public key from the signature
	recoveredPubKey, err := crypto.Ecrecover(hash[:], signature)
	if err != nil {
		return false
	}

	// Compress the recovered public key for comparison
	recoveredPubKeyObj, err := crypto.UnmarshalPubkey(recoveredPubKey)
	if err != nil {
		return false
	}

	compressedRecoveredPubKey := crypto.CompressPubkey(recoveredPubKeyObj)

	// Compare the compressed public keys
	return len(publicKey) == 33 && bytes.Equal(compressedRecoveredPubKey, publicKey)
}

func verifySignatureWithoutV(publicKey, message, signature []byte) bool {
	if len(signature) != 64 || len(publicKey) != 33 || len(message) == 0 {
		return false
	}

	hash := sha256.Sum256(message)

	return crypto.VerifySignature(publicKey, hash[:], signature)
}
