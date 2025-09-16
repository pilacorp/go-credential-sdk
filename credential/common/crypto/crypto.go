package crypto

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/pilacorp/go-credential-sdk/credential/common/jsoncanonicalizer"
)

// KeyToBytes converts a hex string with prefix 0x to a byte array.
func KeyToBytes(key string) ([]byte, error) {
	if !strings.HasPrefix(key, "0x") {
		return nil, errors.New("key is not in hex format")
	}

	return hex.DecodeString(key[2:])
}

// SignMessage signs a message using the provided private key with secp256k1.
func SignMessage(privateKey, message []byte) (string, error) {
	// Create hash of the message
	hash := sha256.Sum256(message)

	// Parse private key
	privKey, err := ParsePrivateKey(privateKey)
	if err != nil {
		return "", err
	}

	signature, err := crypto.Sign(hash[:], privKey)
	if err != nil {
		return "", err
	}

	// Return the signature in hex format
	return hex.EncodeToString(signature), nil
}

// ParsePrivateKey parses a private key of type secp256k1 from bytes
// The length of the private key is 32 bytes.
func ParsePrivateKey(privateKeyBytes []byte) (*ecdsa.PrivateKey, error) {
	if len(privateKeyBytes) != 32 {
		return nil, errors.New("private key must be 32 bytes")
	}

	privKey, err := crypto.ToECDSA(privateKeyBytes)
	if err != nil {
		return nil, err
	}

	return privKey, nil
}

// VerifyJSONSignature verifies the signature of type secp256k1 of a json message
// The message is first canonicalized and then verified.
func VerifyJSONSignature(publicKey, message, signature []byte) bool {
	message, err := jsoncanonicalizer.Transform(message)
	if err != nil {
		return false
	}

	return VerifySignature(publicKey, message, signature)
}

func verifySignatureWithoutV(publicKey, message, signature []byte) bool {
	if len(signature) != 64 || len(publicKey) != 33 || len(message) == 0 {
		return false
	}

	hash := sha256.Sum256(message)

	return crypto.VerifySignature(publicKey, hash[:], signature)
}

// VerifySignature verifies a signature of type secp256k1
// The length of the public key is 33 bytes
// The length of the message is positive
// The length of the signature should be 65 bytes (64 bytes + 1 recovery byte).
func VerifySignature(publicKey, message, signature []byte) bool {
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
