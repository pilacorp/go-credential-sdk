package jwt

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
)

// JWTVerifier handles JWT verification operations for verifiable documents
type JWTVerifier struct {
	resolver *verificationmethod.Resolver
}

// NewJWTVerifier creates a new JWT verifier instance
func NewJWTVerifier(didResolverURL string) *JWTVerifier {
	return &JWTVerifier{
		resolver: verificationmethod.NewResolver(didResolverURL),
	}
}

// VerifyJWT verifies a JWT token and returns the claims as JSONMap
func (v *JWTVerifier) VerifyJWT(tokenString string) error {
	// Split JWT into parts
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	headerEncoded := parts[0]
	payloadEncoded := parts[1]
	signatureEncoded := parts[2]

	// Decode and parse header
	headerBytes, err := base64.RawURLEncoding.DecodeString(headerEncoded)
	if err != nil {
		return fmt.Errorf("failed to decode header: %w", err)
	}

	var header map[string]interface{}
	err = json.Unmarshal(headerBytes, &header)
	if err != nil {
		return fmt.Errorf("failed to unmarshal header: %w", err)
	}

	// Decode and parse payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadEncoded)
	if err != nil {
		return fmt.Errorf("failed to decode payload: %w", err)
	}

	var payload map[string]interface{}
	err = json.Unmarshal(payloadBytes, &payload)
	if err != nil {
		return fmt.Errorf("failed to unmarshal payload: %w", err)
	}

	// Verify signature
	signingString := headerEncoded + "." + payloadEncoded
	signature, err := base64.RawURLEncoding.DecodeString(signatureEncoded)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	// Get public key from header
	publicKey, err := v.getPublicKeyFromHeader(header)
	if err != nil {
		return fmt.Errorf("failed to get public key: %w", err)
	}

	// Verify signature using ES256K
	err = ES256K.Verify(signingString, signature, publicKey)
	if err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}

// getPublicKeyFromHeader retrieves the public key from JWT header
func (v *JWTVerifier) getPublicKeyFromHeader(header map[string]interface{}) (*ecdsa.PublicKey, error) {
	// Check algorithm
	alg, ok := header["alg"].(string)
	if !ok || alg != "ES256K" {
		return nil, fmt.Errorf("unexpected signing method: %v", header["alg"])
	}

	kid, ok := header["kid"].(string)
	if !ok {
		return nil, fmt.Errorf("kid header not found")
	}

	// Use the verification method resolver to get the public key
	publicKeyHex, err := v.resolver.GetPublicKey(kid)
	if err != nil {
		return nil, fmt.Errorf("could not get public key for kid %s: %w", kid, err)
	}

	// Convert hex string to ECDSA public key
	publicKey, err := v.hexToECDSAPublicKey(publicKeyHex)
	if err != nil {
		return nil, fmt.Errorf("could not parse public key for kid %s: %w", kid, err)
	}

	return publicKey, nil
}

// hexToECDSAPublicKey converts a hex string to ECDSA public key
func (v *JWTVerifier) hexToECDSAPublicKey(publicKeyHex string) (*ecdsa.PublicKey, error) {
	// Remove 0x prefix if present
	publicKeyHex = strings.TrimPrefix(publicKeyHex, "0x")

	// Decode hex string
	publicKeyBytes, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key hex: %w", err)
	}

	// Handle compressed public keys (33 bytes starting with 02 or 03)
	if len(publicKeyBytes) == 33 && (publicKeyBytes[0] == 0x02 || publicKeyBytes[0] == 0x03) {
		// Decompress the public key
		publicKey, err := crypto.DecompressPubkey(publicKeyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to decompress public key: %w", err)
		}
		return publicKey, nil
	}

	// Handle uncompressed public keys (65 bytes starting with 04)
	if len(publicKeyBytes) == 65 && publicKeyBytes[0] == 0x04 {
		publicKey, err := crypto.UnmarshalPubkey(publicKeyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal public key: %w", err)
		}
		return publicKey, nil
	}

	return nil, fmt.Errorf("unsupported public key format: length=%d, first_byte=0x%02x", len(publicKeyBytes), publicKeyBytes[0])
}
