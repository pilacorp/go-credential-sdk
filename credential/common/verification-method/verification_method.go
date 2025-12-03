package verificationmethod

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	commoncrypto "github.com/pilacorp/go-credential-sdk/credential/common/crypto"
)

// JWK represents a JSON Web Key structure
type JWK struct {
	Kty string `json:"kty"` // Key type
	Crv string `json:"crv"` // Curve
	X   string `json:"x"`   // X coordinate
	Y   string `json:"y"`   // Y coordinate
}

// VerificationMethodEntry represents a single verification method in a DID Document.
type VerificationMethodEntry struct {
	ID           string `json:"id"`
	Type         string `json:"type"`
	Controller   string `json:"controller"`
	PublicKeyHex string `json:"publicKeyHex,omitempty"`
	PublicKeyJwk *JWK   `json:"publicKeyJwk,omitempty"`
}

// DIDDocument represents the structure of a resolved DID Document.
type DIDDocument struct {
	Context             []string                  `json:"@context"`
	ID                  string                    `json:"id"`
	VerificationMethod  []VerificationMethodEntry `json:"verificationMethod"`
	Authentication      []string                  `json:"authentication"`
	AssertionMethod     []string                  `json:"assertionMethod"`
	Controller          interface{}               `json:"controller"` // Can be string or []string
	DIDDocumentMetadata map[string]interface{}    `json:"didDocumentMetadata"`
}

// Resolver is a client for resolving DIDs from a specific endpoint.
type Resolver struct {
	baseURL string
	client  *http.Client
}

// NewResolver creates a new DID resolver with a given base URL.
func NewResolver(baseURL string) *Resolver {
	return &Resolver{
		baseURL: baseURL,
		client:  &http.Client{Timeout: 10 * time.Second},
	}
}

// GetPublicKey retrieves the public key in hex format for a given verification method URL.
func (r *Resolver) GetPublicKey(verificationMethodURL string) (string, error) {
	// Extract DID from verification method URL
	didPart, _, _ := strings.Cut(verificationMethodURL, "#")
	if didPart == "" {
		return "", fmt.Errorf("invalid verification method URL, could not extract DID: %s", verificationMethodURL)
	}

	// Resolve DID document
	doc, err := r.ResolveToDoc(didPart)
	if err != nil {
		return "", fmt.Errorf("failed to resolve DID '%s': %w", didPart, err)
	}

	// Find matching verification method
	for _, vm := range doc.VerificationMethod {

		if vm.ID == verificationMethodURL {
			// format publicKeyHex
			if vm.PublicKeyHex != "" {
				publicKey := strings.TrimPrefix(vm.PublicKeyHex, "0x")
				return publicKey, nil
			}

			// format publicKeyJwk
			if vm.PublicKeyJwk != nil {
				// Convert JWK to hex format
				hexKey, err := r.jwkToHex(vm.PublicKeyJwk)
				if err != nil {
					return "", fmt.Errorf("failed to convert JWK to hex for verification method '%s': %w", verificationMethodURL, err)
				}
				return hexKey, nil
			}

			return "", fmt.Errorf("no public key found in verification method '%s'", verificationMethodURL)
		}
	}

	return "", fmt.Errorf("verification method '%s' not found in DID document", verificationMethodURL)
}

// jwkToHex converts a JWK to hex format for secp256k1 keys
func (r *Resolver) jwkToHex(jwk *JWK) (string, error) {
	if jwk.Kty != "EC" {
		return "", fmt.Errorf("unsupported key type: %s", jwk.Kty)
	}

	if jwk.Crv != "secp256k1" {
		return "", fmt.Errorf("unsupported curve: %s", jwk.Crv)
	}

	// Decode base64url encoded coordinates
	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return "", fmt.Errorf("failed to decode X coordinate: %w", err)
	}

	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return "", fmt.Errorf("failed to decode Y coordinate: %w", err)
	}

	// Convert to big integers
	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	// Create ECDSA public key
	publicKey := &ecdsa.PublicKey{
		Curve: crypto.S256(),
		X:     x,
		Y:     y,
	}

	// Convert to uncompressed format (0x04 + x + y)
	uncompressed := crypto.FromECDSAPub(publicKey)

	// Return as hex string
	return hex.EncodeToString(uncompressed), nil
}

func (r *Resolver) GetDefaultPublicKey(issuer string) (string, error) {
	// Resolve DID document
	doc, err := r.ResolveToDoc(issuer)
	if err != nil {
		return "", fmt.Errorf("failed to resolve DID '%s': %w", issuer, err)
	}

	if len(doc.VerificationMethod) > 0 {
		vm := doc.VerificationMethod[0]

		// format publicKeyHex
		if vm.PublicKeyHex != "" {
			publicKey := strings.TrimPrefix(vm.PublicKeyHex, "0x")
			return publicKey, nil
		}

		// format publicKeyJwk
		if vm.PublicKeyJwk != nil {
			// Convert JWK to hex format
			hexKey, err := r.jwkToHex(vm.PublicKeyJwk)
			if err != nil {
				return "", fmt.Errorf("failed to convert JWK to hex for DID '%s': %w", issuer, err)
			}
			return hexKey, nil
		}

		return "", fmt.Errorf("no public key found in verification method for DID '%s'", issuer)
	}

	return "", fmt.Errorf("verification method not found in DID '%s' document", issuer)
}

// ResolveToDoc fetches and parses a DID document from the resolver endpoint.
func (r *Resolver) ResolveToDoc(did string) (*DIDDocument, error) {
	// Construct and encode API URL
	encodedDID := url.PathEscape(did)
	apiURL := r.baseURL + "/" + encodedDID

	// Perform HTTP GET request
	resp, err := r.client.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("failed to make HTTP request to DID resolver: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DID resolver API returned non-200 status: %s", resp.Status)
	}

	// Read and parse response
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body from DID resolver: %w", err)
	}

	var doc DIDDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("failed to unmarshal DID document JSON: %w", err)
	}

	return &doc, nil
}

// GetPublicKeyByIssuerAndSignMethod retrieves the public key and verification method ID
// for a given issuer DID and signing method.
func (r *Resolver) GetPublicKeyByIssuerAndSignMethod(issuer, signMethod string) (string, string, error) {
	// Resolve DID document
	doc, err := r.ResolveToDoc(issuer)
	if err != nil {
		return "", "", fmt.Errorf("failed to resolve DID for issuer '%s': %w", issuer, err)
	}

	// Find matching verification method by type
	for _, vm := range doc.VerificationMethod {
		if vm.Type == signMethod {
			// format publicKeyHex
			if vm.PublicKeyHex != "" {
				publicKey := strings.TrimPrefix(vm.PublicKeyHex, "0x")
				return publicKey, vm.ID, nil
			}

			// format publicKeyJwk
			if vm.PublicKeyJwk != nil {
				// Convert JWK to hex format
				hexKey, err := r.jwkToHex(vm.PublicKeyJwk)
				if err != nil {
					return "", "", fmt.Errorf("failed to convert JWK to hex for issuer '%s': %w", issuer, err)
				}
				return hexKey, vm.ID, nil
			}

			return "", "", fmt.Errorf("no public key found in verification method for issuer '%s' with sign method '%s'", issuer, signMethod)
		}
	}

	return "", "", fmt.Errorf("no public key found for issuer '%s' with sign method '%s'", issuer, signMethod)
}

// GetDIDFromVerificationMethod extracts the DID from a verification method URL.
func (r *Resolver) GetDIDFromVerificationMethod(verificationMethod string) (string, error) {
	if verificationMethod == "" {
		return "", fmt.Errorf("verification method is empty")
	}

	// Extract DID by removing fragment
	didPart, _, found := strings.Cut(verificationMethod, "#")
	if !found || didPart == "" {
		return "", fmt.Errorf("invalid verification method URL, could not extract DID: %s", verificationMethod)
	}

	// Validate DID prefix
	if !strings.HasPrefix(didPart, "did:") {
		return "", fmt.Errorf("extracted DID '%s' is invalid, must start with 'did:'", didPart)
	}

	return didPart, nil
}

// CheckVerificationMethod verifies if the provided private key matches the public key
// associated with the given verification method in its DID document.
func (r *Resolver) CheckVerificationMethod(privateKey, verificationMethod string) (bool, error) {
	// Validate inputs
	if privateKey == "" || verificationMethod == "" {
		return false, fmt.Errorf("private key or verification method is empty")
	}

	// Get public key from verification method
	publicKey, err := r.GetPublicKey(verificationMethod)
	if err != nil {
		return false, fmt.Errorf("failed to Get Public Key pair for '%s': %w", verificationMethod, err)
	}

	// Verify key pair
	if isValid, err := commoncrypto.VerifyKeyPairFromHex(privateKey, publicKey); err != nil {
		return false, fmt.Errorf("failed to verify key pair for '%s': %w", verificationMethod, err)
	} else {
		return isValid, nil
	}
}
