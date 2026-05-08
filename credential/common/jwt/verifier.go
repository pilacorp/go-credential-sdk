package jwt

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
)

// JWTVerifier handles JWT verification operations
type JWTVerifier struct {
	docResolver        verificationmethod.ResolverProvider
	strictProofPurpose bool
}

// VerifierOption mutates JWTVerifier construction.
type VerifierOption func(*JWTVerifier)

// WithStrictProofPurpose toggles strict proofPurpose checking. Default ON.
// Strict checks require a non-nil docResolver; constructions without one
// (e.g. token-only flows) fall back to crypto-only verification regardless
// of this flag.
func WithStrictProofPurpose(strict bool) VerifierOption {
	return func(v *JWTVerifier) {
		v.strictProofPurpose = strict
	}
}

// NewJWTVerifier creates a new JWT verifier with DID resolver (kept for backward compatibility).
func NewJWTVerifier(didResolverURL string, opts ...VerifierOption) *JWTVerifier {
	v := &JWTVerifier{
		docResolver:        verificationmethod.NewHTTPResolver(didResolverURL),
		strictProofPurpose: true,
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

func NewJWTVerifierWithResolver(
	docResolver verificationmethod.ResolverProvider,
	opts ...VerifierOption,
) *JWTVerifier {
	v := &JWTVerifier{
		docResolver:        docResolver,
		strictProofPurpose: true,
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
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

	kid, ok := header["kid"].(string)
	if !ok {
		return fmt.Errorf("kid not found in header")
	}

	if v.docResolver == nil {
		return fmt.Errorf("document resolver is not configured")
	}

	// Resolve the document by the issuer DID claimed in the JWT body, not
	// by the DID prefix of `kid`. The `iss` claim is the authoritative
	// identifier of the signer; FindVerificationMethod will reject if the
	// kid does not actually belong to that issuer's document.
	issuer, derr := jwtIssuer(parts[1])
	if derr != nil {
		return derr
	}
	doc, derr := v.docResolver.ResolveDocument(context.Background(), issuer)
	if derr != nil {
		return fmt.Errorf("failed to resolve DID document for issuer '%s': %w", issuer, derr)
	}
	vm, verr := verificationmethod.FindVerificationMethod(doc, kid)
	if verr != nil {
		return fmt.Errorf("failed to resolve verification method: %w", verr)
	}

	publicKeyHex, err := publicKeyHexFromVM(vm)
	if err != nil {
		return err
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

	if err := ES256K.Verify(signingString, signature, publicKey); err != nil {
		return err
	}

	// Strict-purpose check is only meaningful when we actually resolved a
	// VM from a real DID document. JWT credentials always sign over VCs
	// with proofPurpose = assertionMethod (W3C VC Data Integrity); JWTs
	// over VPs use authentication. Detect from the JWT body's first claim.
	if v.strictProofPurpose {
		purpose, perr := jwtProofPurpose(parts[1])
		if perr != nil {
			return perr
		}
		issuedAt, ierr := jwtIssuedAt(parts[1])
		if ierr != nil {
			return ierr
		}
		if err := strictPurposeCheck(doc, vm, purpose, issuedAt); err != nil {
			return err
		}
	}
	return nil
}

// jwtProofPurpose returns the proofPurpose to enforce for the JWT body —
// assertionMethod for credentials (presence of "vc" claim) and
// authentication for presentations ("vp"). Returns an error if neither is
// present.
func jwtProofPurpose(payloadB64 string) (string, error) {
	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return "", fmt.Errorf("invalid payload encoding: %w", err)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &body); err != nil {
		return "", fmt.Errorf("invalid payload JSON: %w", err)
	}
	if _, ok := body["vc"]; ok {
		return "assertionMethod", nil
	}
	if _, ok := body["vp"]; ok {
		return "authentication", nil
	}
	return "", fmt.Errorf("JWT body has neither vc nor vp claim; cannot determine proofPurpose")
}

// jwtIssuer extracts the issuer DID from the `iss` claim in the JWT body.
// Per W3C VC Data Model JWT encoding, both VC JWTs (issuer DID) and VP
// JWTs (holder DID) put the signer DID in `iss`. The verifier resolves
// the DID Document via this claim rather than the kid header so the
// authoritative source is the signed body, not a key identifier hint.
func jwtIssuer(payloadB64 string) (string, error) {
	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return "", fmt.Errorf("invalid payload encoding: %w", err)
	}
	var body struct {
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(payloadBytes, &body); err != nil {
		return "", fmt.Errorf("invalid payload JSON: %w", err)
	}
	if body.Iss == "" {
		return "", fmt.Errorf("JWT body is missing required `iss` claim")
	}
	return body.Iss, nil
}

// jwtIssuedAt extracts iat (issued at) as UTC time when present.
// Returns (nil, nil) when iat is absent.
func jwtIssuedAt(payloadB64 string) (*time.Time, error) {
	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, fmt.Errorf("invalid payload encoding: %w", err)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &body); err != nil {
		return nil, fmt.Errorf("invalid payload JSON: %w", err)
	}

	raw, ok := body["iat"]
	if !ok || raw == nil {
		return nil, nil
	}

	var sec int64
	switch t := raw.(type) {
	case float64:
		sec = int64(t)
	case int64:
		sec = t
	case json.Number:
		v, err := t.Int64()
		if err != nil {
			return nil, fmt.Errorf("invalid iat: %v", err)
		}
		sec = v
	default:
		return nil, fmt.Errorf("invalid iat type: %T", raw)
	}

	if sec <= 0 {
		return nil, fmt.Errorf("invalid iat value: %v", raw)
	}

	tm := time.Unix(sec, 0).UTC()
	return &tm, nil
}

// strictPurposeCheck mirrors the post-crypto checks used by jsonmap.VerifyProof
// for embedded ECDSA proofs. JWTs do not carry a proof.created field, so the
// timestamp check is omitted here — verifiers that need it should encode the
// signing time as `iat` and add their own enforcement.
func strictPurposeCheck(doc *verificationmethod.DIDDocument, vm *verificationmethod.VerificationMethodEntry, proofPurpose string, issuedAt *time.Time) error {
	if verificationmethod.IsHardRevocationReason(vm.RevocationReason) {
		return fmt.Errorf("verification method '%s' revoked with hard reason '%s'", vm.ID, vm.RevocationReason)
	}
	if vm.Revoked != nil {
		if issuedAt == nil {
			return fmt.Errorf("verification method '%s' was revoked at %s (missing iat for time-based revocation check)",
				vm.ID, vm.Revoked.UTC().Format(time.RFC3339))
		}
		if !issuedAt.Before(*vm.Revoked) {
			return fmt.Errorf("verification method '%s' was revoked at %s; iat %s is not earlier",
				vm.ID, vm.Revoked.UTC().Format(time.RFC3339), issuedAt.UTC().Format(time.RFC3339))
		}
	}

	var arr []string
	switch proofPurpose {
	case "authentication":
		arr = doc.Authentication
	case "assertionMethod":
		arr = doc.AssertionMethod
	default:
		return fmt.Errorf("unsupported proofPurpose '%s'", proofPurpose)
	}
	frag := vm.ID
	if i := len(doc.ID); len(vm.ID) > i && vm.ID[:i] == doc.ID && vm.ID[i] == '#' {
		frag = vm.ID[i:]
	}
	for _, ref := range arr {
		if ref == vm.ID || ref == frag {
			return nil
		}
	}
	return fmt.Errorf("verification method '%s' is not granted purpose '%s' on DID '%s'", vm.ID, proofPurpose, doc.ID)
}

func publicKeyHexFromVM(vm *verificationmethod.VerificationMethodEntry) (string, error) {
	if vm == nil {
		return "", fmt.Errorf("verification method is nil")
	}
	if vm.PublicKeyHex != "" {
		return strings.TrimPrefix(vm.PublicKeyHex, "0x"), nil
	}
	if vm.PublicKeyJwk != nil {
		return verificationmethod.JWKToHex(vm.PublicKeyJwk)
	}
	return "", fmt.Errorf("verification method '%s' has no public key material", vm.ID)
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
