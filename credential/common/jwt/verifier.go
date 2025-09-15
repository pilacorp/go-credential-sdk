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

// JWTVerifier handles JWT verification operations
type JWTVerifier struct {
	resolver *verificationmethod.Resolver
}

// NewJWTVerifier creates a new JWT verifier with DID resolver
func NewJWTVerifier(didResolverURL string) *JWTVerifier {
	return &JWTVerifier{
		resolver: verificationmethod.NewResolver(didResolverURL),
	}
}

// VerifyJWT verifies a JWT token
func (v *JWTVerifier) VerifyJWT(tokenString string) error {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid JWT format")
	}

	// Decode header to get kid
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("invalid header: %w", err)
	}

	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return fmt.Errorf("invalid header: %w", err)
	}

	kid, ok := header["kid"].(string)
	if !ok {
		return fmt.Errorf("kid not found in header")
	}

	// Get public key from resolver
	publicKeyHex, err := v.resolver.GetPublicKey(kid)
	if err != nil {
		return fmt.Errorf("failed to get public key: %w", err)
	}

	publicKey, err := hexToECDSAPublicKey(publicKeyHex)
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}

	signingString := parts[0] + "." + parts[1]
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("invalid signature: %w", err)
	}

	return ES256K.Verify(signingString, signature, publicKey)
}

// hexToECDSAPublicKey converts hex string to ECDSA public key
func hexToECDSAPublicKey(publicKeyHex string) (*ecdsa.PublicKey, error) {
	publicKeyHex = strings.TrimPrefix(publicKeyHex, "0x")

	publicKeyBytes, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex: %w", err)
	}

	// Handle compressed public keys (33 bytes)
	if len(publicKeyBytes) == 33 && (publicKeyBytes[0] == 0x02 || publicKeyBytes[0] == 0x03) {
		return crypto.DecompressPubkey(publicKeyBytes)
	}

	// Handle uncompressed public keys (65 bytes)
	if len(publicKeyBytes) == 65 && publicKeyBytes[0] == 0x04 {
		return crypto.UnmarshalPubkey(publicKeyBytes)
	}

	return nil, fmt.Errorf("unsupported public key format")
}
