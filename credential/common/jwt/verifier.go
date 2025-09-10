package jwt

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/golang-jwt/jwt/v5"
	"github.com/pilacorp/go-credential-sdk/credential/common/jsonmap"
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
func (v *JWTVerifier) VerifyJWT(tokenString string) (jsonmap.JSONMap, error) {
	// Register the ES256K signing method
	jwt.RegisterSigningMethod(ES256K.Alg(), func() jwt.SigningMethod {
		return ES256K
	})

	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, v.getKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("token is invalid")
	}

	return jsonmap.JSONMap(claims), nil
}

// VerifyDocument verifies a verifiable document JWT and returns the document as JSONMap
func (v *JWTVerifier) VerifyDocument(tokenString string, docType string) (jsonmap.JSONMap, error) {
	claims, err := v.VerifyJWT(tokenString)
	if err != nil {
		return nil, err
	}

	// Extract the document from claims (try both vc and vp)
	var docData interface{}
	docData, ok := claims[docType]
	if !ok {
		return nil, fmt.Errorf("%s claim not found in JWT", docType)
	}

	docJSONMap, ok := docData.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("verifiable document is not a valid JSON object")
	}

	return jsonmap.JSONMap(docJSONMap), nil
}

// getKey retrieves the public key for JWT verification
func (v *JWTVerifier) getKey(token *jwt.Token) (interface{}, error) {
	if _, ok := token.Method.(*SigningMethodES256K); !ok {
		return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	}

	kid, ok := token.Header["kid"].(string)
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
