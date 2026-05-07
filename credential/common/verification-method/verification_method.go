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
//
// Revoked and RevocationReason are Pila extensions that follow the W3C MAY
// guidance for additional properties. Reason values follow RFC 5280 §5.3.1
// (CRL Reason Codes); see common/proof for hard vs soft semantics.
type VerificationMethodEntry struct {
	ID               string     `json:"id"`
	Type             string     `json:"type"`
	Controller       string     `json:"controller"`
	PublicKeyHex     string     `json:"publicKeyHex,omitempty"`
	PublicKeyJwk     *JWK       `json:"publicKeyJwk,omitempty"`
	Revoked          *time.Time `json:"revoked,omitempty"`
	RevocationReason string     `json:"revocationReason,omitempty"`
}

// IsActive reports whether the verification method is currently usable for
// signing — i.e. it has not been marked revoked.
func (vm *VerificationMethodEntry) IsActive() bool {
	return vm.Revoked == nil
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

var defaultHTTPClient = &http.Client{
	Timeout: 10 * time.Second,
}

type Option func(*Resolver)

func WithHTTPClient(client *http.Client) Option {
	return func(r *Resolver) {
		if client == nil {
			return
		}

		r.client = client
	}
}

// NewResolver creates a new DID resolver with a given base URL.
func NewResolver(baseURL string, opts ...Option) *Resolver {
	resolver := &Resolver{
		baseURL: baseURL,
		client:  defaultHTTPClient,
	}

	for _, opt := range opts {
		opt(resolver)
	}

	return resolver
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

// JWKToHex converts a secp256k1 JWK to its uncompressed hex representation
// (0x04 || X || Y). Exposed for callers that already have a JWK in hand and
// want to avoid going through the resolver's HTTP path.
func JWKToHex(jwk *JWK) (string, error) {
	if jwk.Kty != "EC" {
		return "", fmt.Errorf("unsupported key type: %s", jwk.Kty)
	}

	if jwk.Crv != "secp256k1" {
		return "", fmt.Errorf("unsupported curve: %s", jwk.Crv)
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return "", fmt.Errorf("failed to decode X coordinate: %w", err)
	}

	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return "", fmt.Errorf("failed to decode Y coordinate: %w", err)
	}

	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	publicKey := &ecdsa.PublicKey{
		Curve: crypto.S256(),
		X:     x,
		Y:     y,
	}

	uncompressed := crypto.FromECDSAPub(publicKey)
	return hex.EncodeToString(uncompressed), nil
}

// jwkToHex is kept as a method shim for backward compatibility.
func (r *Resolver) jwkToHex(jwk *JWK) (string, error) {
	return JWKToHex(jwk)
}

// Deprecated: GetDefaultPublicKey returns the public key of verificationMethod[0],
// which is correct only for single-VM DIDs. Multi-VM callers should resolve the
// verification method by URL via GetPublicKey, or pick a key for a specific
// purpose via GetVerificationMethodByPurpose.
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

// ResolveDocumentAndVM resolves the DID Document referenced by the given
// verification method URL and returns both the document and the matching
// verification method entry. Verifiers use this to access Revoked /
// RevocationReason and to check relationship array membership for the
// proof's purpose without re-fetching the document.
func (r *Resolver) ResolveDocumentAndVM(verificationMethodURL string) (*DIDDocument, *VerificationMethodEntry, error) {
	didPart, _, _ := strings.Cut(verificationMethodURL, "#")
	if didPart == "" {
		return nil, nil, fmt.Errorf("invalid verification method URL, could not extract DID: %s", verificationMethodURL)
	}

	doc, err := r.ResolveToDoc(didPart)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to resolve DID '%s': %w", didPart, err)
	}

	for i := range doc.VerificationMethod {
		vm := &doc.VerificationMethod[i]
		if vm.ID == verificationMethodURL {
			return doc, vm, nil
		}
		// Allow lookup by fragment alone if URL is a fragment ("#key-1") and
		// the doc id matches.
		if strings.HasPrefix(verificationMethodURL, "#") && vm.ID == doc.ID+verificationMethodURL {
			return doc, vm, nil
		}
	}

	return doc, nil, fmt.Errorf("verification method '%s' not found in DID document", verificationMethodURL)
}

// GetVerificationMethodByPurpose picks the latest active VM in the relationship
// array for the given purpose ("authentication" or "assertionMethod") and
// returns its hex public key plus its full URL id. "Latest" follows Pila's
// `#key-N` convention: the VM with the highest sequential N that is active
// (Revoked == nil) and listed in the purpose array.
//
// Returns error if no matching VM exists. Used by SDK Sign as the default
// when caller does not pass WithVerificationMethodKey. Internally fetches
// the document via HTTP — callers that already have a resolved document
// should call SelectLatestActiveVMForPurpose directly.
func (r *Resolver) GetVerificationMethodByPurpose(did, purpose string) (publicKeyHex, vmID string, err error) {
	doc, err := r.ResolveToDoc(did)
	if err != nil {
		return "", "", fmt.Errorf("failed to resolve DID '%s': %w", did, err)
	}

	vm, err := SelectLatestActiveVMForPurpose(doc, purpose)
	if err != nil {
		return "", "", err
	}

	pub, err := publicKeyFromVM(vm, r)
	if err != nil {
		return "", "", err
	}
	return pub, vm.ID, nil
}

// SelectLatestActiveVMForPurpose picks the active verification method that
// holds the given purpose ("authentication" or "assertionMethod") and has the
// highest sequential `#key-N` index. Pila's append-only DID document grows by
// adding higher-numbered fragments on each rotation; picking the maximum N
// yields the most recently issued key. VMs whose id does not follow the
// `#key-N` convention are still considered but ranked as 0, so any explicit
// `#key-N` entry wins.
//
// Returns error if doc is nil, the purpose is unsupported, the relationship
// array is empty, or no listed VM is active.
//
// Callers that have already fetched a document (e.g. from a gRPC resolver
// service) should use this free function instead of going through HTTP via
// Resolver.GetVerificationMethodByPurpose.
func SelectLatestActiveVMForPurpose(doc *DIDDocument, purpose string) (*VerificationMethodEntry, error) {
	if doc == nil {
		return nil, fmt.Errorf("did document is nil")
	}

	var purposeArr []string
	switch purpose {
	case "authentication":
		purposeArr = doc.Authentication
	case "assertionMethod":
		purposeArr = doc.AssertionMethod
	default:
		return nil, fmt.Errorf("unsupported purpose: %s", purpose)
	}

	if len(purposeArr) == 0 {
		return nil, fmt.Errorf("no verification methods listed for purpose '%s' on DID '%s'", purpose, doc.ID)
	}

	var bestVM *VerificationMethodEntry
	bestN := -1
	for i := range doc.VerificationMethod {
		vm := &doc.VerificationMethod[i]
		if !vm.IsActive() {
			continue
		}
		if !idInPurposeArray(vm.ID, doc.ID, purposeArr) {
			continue
		}
		n, ok := parseSequentialFragment(vm.ID, doc.ID)
		if !ok {
			n = 0
		}
		if n > bestN {
			bestN = n
			bestVM = vm
		}
	}

	if bestVM == nil {
		return nil, fmt.Errorf("no active verification method for purpose '%s' on DID '%s'", purpose, doc.ID)
	}
	return bestVM, nil
}

// SelectVMForPurpose selects a verification method for the given purpose from a
// resolved DID document.
//
// Rules:
//   - If kid is empty (legacy tokens), it defaults to the latest *active* VM that
//     is authorized for the requested purpose (per SelectLatestActiveVMForPurpose).
//   - If kid is provided, the VM is looked up by id (full URL) or fragment form
//     ("#key-2"). The selected VM may be revoked; callers should apply revocation
//     timing and purpose authorization checks separately.
//
// This helper is intentionally local (doc-based) so callers that already have a
// resolved document (e.g. via gRPC) can avoid the SDK's HTTP resolver.
func SelectVMForPurpose(doc *DIDDocument, purpose, kid string) (*VerificationMethodEntry, error) {
	if kid == "" {
		return SelectLatestActiveVMForPurpose(doc, purpose)
	}
	if doc == nil {
		return nil, fmt.Errorf("did document is nil")
	}

	vmID := kid

	for i := range doc.VerificationMethod {
		vm := &doc.VerificationMethod[i]
		if vm.ID == vmID {
			return vm, nil
		}
	}

	return nil, fmt.Errorf("verification method '%s' not found in DID '%s' document", vmID, doc.ID)
}

// idInPurposeArray reports whether the VM id (or its fragment form) appears
// in the relationship array.
func idInPurposeArray(vmID, did string, arr []string) bool {
	frag := vmID
	if strings.HasPrefix(vmID, did+"#") {
		frag = strings.TrimPrefix(vmID, did)
	}
	for _, ref := range arr {
		if ref == vmID || ref == frag {
			return true
		}
	}
	return false
}

// parseSequentialFragment extracts N from a VM id of the form "<did>#key-N".
func parseSequentialFragment(vmID, did string) (int, bool) {
	prefix := did + "#key-"
	if !strings.HasPrefix(vmID, prefix) {
		return 0, false
	}
	var n int
	if _, err := fmt.Sscanf(vmID[len(prefix):], "%d", &n); err != nil {
		return 0, false
	}
	return n, true
}

// publicKeyFromVM returns the hex public key encoded in vm, decoding from
// publicKeyJwk via the resolver's helper if publicKeyHex is absent.
func publicKeyFromVM(vm *VerificationMethodEntry, r *Resolver) (string, error) {
	if vm.PublicKeyHex != "" {
		return strings.TrimPrefix(vm.PublicKeyHex, "0x"), nil
	}
	if vm.PublicKeyJwk != nil {
		return r.jwkToHex(vm.PublicKeyJwk)
	}
	return "", fmt.Errorf("no public key material on verification method '%s'", vm.ID)
}
