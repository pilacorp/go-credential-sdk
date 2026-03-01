package jwt

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
)

// JWTVerifier handles JWT verification operations
type JWTVerifier struct {
	resolver     *verificationmethod.Resolver
	publicKeyHex string
}

// Option configures JWTVerifier
type Option func(*JWTVerifier)

// WithDIDResolverURL sets the DID resolver from URL
func WithDIDResolverURL(url string) Option {
	return func(v *JWTVerifier) {
		v.resolver = verificationmethod.NewResolver(url)
	}
}

// WithResolver sets the verification method resolver
func WithResolver(r *verificationmethod.Resolver) Option {
	return func(v *JWTVerifier) {
		v.resolver = r
	}
}

// WithPublicKeyHex sets the public key hex (for verification without DID resolution)
func WithPublicKeyHex(hex string) Option {
	return func(v *JWTVerifier) {
		v.publicKeyHex = hex
	}
}

// NewJWTVerifier creates a new JWT verifier with DID resolver (kept for backward compatibility)
func NewJWTVerifier(didResolverURL string) *JWTVerifier {
	return &JWTVerifier{
		resolver: verificationmethod.NewResolver(didResolverURL),
	}
}

// NewJWTVerifierWithOptions creates a new JWT verifier with optional configuration.
// Returns an error if no resolver or public key is configured.
func NewJWTVerifierWithOptions(opts ...Option) (*JWTVerifier, error) {
	v := &JWTVerifier{}
	for _, opt := range opts {
		opt(v)
	}

	if v.resolver == nil && v.publicKeyHex == "" {
		return nil, errors.New("JWTVerifier requires either WithDIDResolverURL/WithResolver or WithPublicKeyHex")
	}

	return v, nil
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

	// Check algorithm
	alg, ok := header["alg"].(string)
	if !ok || alg != "ES256K" {
		return fmt.Errorf("unsupported algorithm: %v", header["alg"])
	}

	var publicKeyHex string
	if v.publicKeyHex != "" {
		// Use configured public key directly, no need to resolve
		publicKeyHex = v.publicKeyHex
	} else {
		// Get public key from resolver
		kid, ok := header["kid"].(string)
		if !ok {
			return fmt.Errorf("kid not found in header")
		}
		if v.resolver == nil {
			return fmt.Errorf("no resolver or public key configured")
		}
		var err error
		publicKeyHex, err = v.resolver.GetPublicKey(kid)
		if err != nil {
			return fmt.Errorf("failed to get public key: %w", err)
		}
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
