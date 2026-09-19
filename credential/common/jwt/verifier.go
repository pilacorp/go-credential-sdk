package jwt

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
)

// JWTVerifier handles JWT verification operations. It always enforces the
// strict-purpose check after crypto verification.
type JWTVerifier struct {
	docResolver verificationmethod.ResolverProvider
}

// VerifierOption mutates JWTVerifier construction.
type VerifierOption func(*JWTVerifier)

func NewJWTVerifier(
	docResolver verificationmethod.ResolverProvider,
	opts ...VerifierOption,
) *JWTVerifier {
	v := &JWTVerifier{
		docResolver: docResolver,
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

	alg, ok := header["alg"].(string)
	if !ok || (alg != AlgES256K && alg != AlgES256) {
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

	// The header must not claim an algorithm the verification method's key
	// cannot produce, otherwise alg and key could be mixed.
	kind, kok := verificationmethod.VMKeyKind(vm)
	if !kok {
		return fmt.Errorf("verification method '%s' has an unrecognized key type", vm.ID)
	}
	wantAlg, aerr := AlgForKeyKind(kind)
	if aerr != nil {
		return fmt.Errorf("verification method '%s': %w", vm.ID, aerr)
	}
	if alg != wantAlg {
		return fmt.Errorf("JWT alg %q does not match verification method '%s', which holds a %s key", alg, vm.ID, kind)
	}

	publicKey, err := verificationmethod.ECPubFromVM(vm)
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}

	signingString := parts[0] + "." + parts[1]
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("invalid signature: %w", err)
	}

	// alg was matched to the VM's key above, so publicKey is already on the
	// curve alg names; ES256K and ES256 share the same ECDSA check.
	if err := VerifyECDSA(signingString, signature, publicKey); err != nil {
		return err
	}

	// Strict-purpose check (always on): JWT VCs use proofPurpose =
	// assertionMethod, JWT VPs use authentication. Detect from the JWT
	// header typ or body's claims.
	purpose, perr := jwtProofPurpose(header, parts[1])
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
	return nil
}

// jwtProofPurpose returns the proofPurpose to enforce for the JWT —
// assertionMethod for credentials and authentication for presentations.
// Detects from header typ (vc+jwt / vp+jwt per W3C vc-jose-cose) or
// payload claims (vc / vp per W3C VC 1.1, or type array).
func jwtProofPurpose(header map[string]interface{}, payloadB64 string) (string, error) {
	if typ, ok := header["typ"].(string); ok {
		switch typ {
		case "vc+jwt", "application/vc+jwt":
			return "assertionMethod", nil
		case "vp+jwt", "application/vp+jwt":
			return "authentication", nil
		}
	}

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
	if types, ok := body["type"].([]interface{}); ok {
		for _, t := range types {
			if str, ok := t.(string); ok {
				if str == "VerifiableCredential" {
					return "assertionMethod", nil
				}
				if str == "VerifiablePresentation" {
					return "authentication", nil
				}
			}
		}
	} else if typeStr, ok := body["type"].(string); ok {
		if typeStr == "VerifiableCredential" {
			return "assertionMethod", nil
		}
		if typeStr == "VerifiablePresentation" {
			return "authentication", nil
		}
	}
	return "", fmt.Errorf("JWT has neither vc/vp claims nor vc+jwt/vp+jwt typ; cannot determine proofPurpose")
}

// jwtIssuer extracts the issuer DID from the JWT body.
// Per W3C VC Data Model v1.1 JWT encoding, both VC JWTs (issuer DID) and VP
// JWTs (holder DID) put the signer DID in `iss`.
// Per W3C VC 2.0 vc-jose-cose, the unsecured VC/VP is the unencoded payload,
// so the signer DID is in `issuer` (for VC) or `holder` (for VP) if `iss` is omitted.
func jwtIssuer(payloadB64 string) (string, error) {
	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return "", fmt.Errorf("invalid payload encoding: %w", err)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &body); err != nil {
		return "", fmt.Errorf("invalid payload JSON: %w", err)
	}
	// 1. Check standard JWT "iss" claim
	if iss, ok := body["iss"].(string); ok && iss != "" {
		return iss, nil
	}
	// 2. Check VC 2.0 "issuer" field
	if issuer, ok := body["issuer"].(string); ok && issuer != "" {
		return issuer, nil
	}
	if issuerObj, ok := body["issuer"].(map[string]interface{}); ok {
		if id, ok := issuerObj["id"].(string); ok && id != "" {
			return id, nil
		}
	}
	// 3. Check VP 2.0 "holder" field
	if holder, ok := body["holder"].(string); ok && holder != "" {
		return holder, nil
	}
	if holderObj, ok := body["holder"].(map[string]interface{}); ok {
		if id, ok := holderObj["id"].(string); ok && id != "" {
			return id, nil
		}
	}
	return "", fmt.Errorf("JWT body is missing required signer identifier (iss/issuer/holder)")
}

// jwtIssuedAt extracts iat (issued at) as UTC time when present.
// Fallbacks to validFrom when iat is absent.
// Returns (nil, nil) when both are absent.
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
	if ok && raw != nil {
		var sec int64
		switch t := raw.(type) {
		case float64:
			sec = int64(t)
		case int64:
			sec = t
		case json.Number:
			var err error
			sec, err = t.Int64()
			if err != nil {
				return nil, fmt.Errorf("invalid iat value: %w", err)
			}
		default:
			return nil, fmt.Errorf("invalid iat type: %T", raw)
		}
		if sec <= 0 {
			return nil, fmt.Errorf("invalid iat value: %v", raw)
		}
		tm := time.Unix(sec, 0).UTC()
		return &tm, nil
	}

	// Fallback to validFrom if iat is absent (common in VC 2.0 vc-jose-cose)
	if vf, ok := body["validFrom"].(string); ok && vf != "" {
		if t, err := time.Parse(time.RFC3339Nano, vf); err == nil {
			utc := t.UTC()
			return &utc, nil
		}
		if t, err := time.Parse(time.RFC3339, vf); err == nil {
			utc := t.UTC()
			return &utc, nil
		}
	}

	return nil, nil
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
