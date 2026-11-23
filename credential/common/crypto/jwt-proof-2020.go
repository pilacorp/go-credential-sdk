package crypto

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
)

// ErrJwtProofBinding is returned when the JWT payload does not cover
// the credential body the proof is attached to. Use errors.Is to test.
var ErrJwtProofBinding = errors.New("JwtProof2020 body binding failed")

// VerifyJwtProofToken verifies a JwtProof2020 proof: it checks that the JWT
// was signed by pub and that the JWT payload covers the credential/presentation
// body. On success it returns the signed time (iat, else nbf) from the JWT
// payload; a zero time means neither claim was present. body is the full
// document map (the proof key is ignored during the coverage check).
func VerifyJwtProofToken(body map[string]interface{}, jwtToken string, pub *ecdsa.PublicKey) (time.Time, error) {
	if jwtToken == "" {
		return time.Time{}, fmt.Errorf("JWT token is missing")
	}
	if pub == nil {
		return time.Time{}, fmt.Errorf("public key is nil")
	}

	signature, message, err := getSignatureAndMessage(jwtToken)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to extract signature and message from JWT: %w", err)
	}

	if !verifySignature(crypto.CompressPubkey(pub), message, signature) {
		return time.Time{}, fmt.Errorf("JWT signature verification failed")
	}

	claims, err := verifyJwtBodyBinding(jwtToken, body)
	if err != nil {
		return time.Time{}, err
	}

	return jwtSignedTime(claims), nil
}

// VerifyJwtProof is the legacy entry point. It extracts the JWT from the proof
// field in req and delegates to VerifyJwtProofToken. It is safe to call when
// proof is an array or any other non-object: it returns an error, never a panic.
func VerifyJwtProof(req *map[string]interface{}, pub *ecdsa.PublicKey) (bool, error) {
	jwtToken, err := extractJwtFromProof(*req)
	if err != nil {
		return false, err
	}
	_, err = VerifyJwtProofToken(*req, jwtToken, pub)
	if err != nil {
		return false, err
	}
	return true, nil
}

// JwtKid extracts the kid claim from the JWT header, if present.
func JwtKid(jwtToken string) (string, bool) {
	dot := strings.IndexByte(jwtToken, '.')
	if dot <= 0 {
		return "", false
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(jwtToken[:dot])
	if err != nil {
		return "", false
	}
	var hdr struct {
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerBytes, &hdr); err != nil {
		return "", false
	}
	return hdr.Kid, hdr.Kid != ""
}

// extractJwtFromProof safely extracts the JWT string from the proof field.
// Returns an error (never panics) if the proof is not a JSON object or has no
// jwt field.
func extractJwtFromProof(body map[string]interface{}) (string, error) {
	raw, ok := body["proof"]
	if !ok || raw == nil {
		return "", fmt.Errorf("JWT token is missing")
	}
	proofMap, ok := raw.(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("JWT token is missing")
	}
	jwt, ok := proofMap["jwt"].(string)
	if !ok || jwt == "" {
		return "", fmt.Errorf("JWT token is missing")
	}
	return jwt, nil
}

// verifyJwtBodyBinding decodes the JWT payload and checks that every member of
// the credential/presentation body (minus proof) is covered by the JWT: either
// directly in the vc/vp claim or via the VC-JWT 1.1 moved-field mapping.
// On success it returns the full JWT claims map so the caller can extract
// signed timestamps (iat, nbf).
func verifyJwtBodyBinding(jwtToken string, body map[string]interface{}) (map[string]interface{}, error) {
	parts := strings.Split(jwtToken, ".")
	if len(parts) != 3 {
		return nil, bindingErr("invalid JWT format")
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, bindingErr("failed to decode JWT payload")
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, bindingErr("failed to parse JWT payload")
	}

	isVP := bodyIsPresentation(body)

	claimKey := "vc"
	if isVP {
		claimKey = "vp"
	}

	raw, ok := claims[claimKey]
	if !ok {
		return nil, bindingErr(fmt.Sprintf("JWT payload has no %s claim", claimKey))
	}
	container, ok := raw.(map[string]interface{})
	if !ok {
		return nil, bindingErr(fmt.Sprintf("JWT %s claim is not a JSON object", claimKey))
	}

	// Check 2: every body member (except proof) must be covered.
	for k, bodyVal := range body {
		if k == "proof" {
			continue
		}
		if cVal, inContainer := container[k]; inContainer {
			if jsonDeepEqual(bodyVal, cVal) {
				continue
			}
			// credentialSubject may differ only by the id field, which
			// VC-JWT 1.1 §6.3.1 moves to the sub claim.
			if !isVP && k == "credentialSubject" {
				if err := checkSubjectIDMovedToSub(bodyVal, cVal, claims); err != nil {
					return nil, err
				}
				continue
			}
			return nil, memberErr(k)
		}
		// Not in the container claim: check if it is a moved field.
		if isVP {
			if err := checkMovedFieldVP(k, bodyVal, claims); err != nil {
				return nil, err
			}
		} else {
			if err := checkMovedField(k, bodyVal, claims); err != nil {
				return nil, err
			}
		}
	}

	// Check 4: a container member that the body lacks, or a proof member
	// inside the container, makes the proof fail.
	for k := range container {
		if k == "proof" {
			return nil, memberErr(k)
		}
		if _, inBody := body[k]; !inBody {
			return nil, memberErr(k)
		}
	}

	// Check 5: each moved claim the JWT signs must have a corresponding
	// member in the body. Without this, a body that silently drops e.g.
	// expirationDate still verifies, and WithCheckExpiration (which reads
	// only the body) lets an expired credential through.
	if isVP {
		if _, ok := claims["jti"]; ok && body["id"] == nil {
			return nil, memberErr("id")
		}
	} else {
		for claim, members := range map[string][]string{
			"jti": {"id"},
			"nbf": {"issuanceDate", "validFrom"},
			"exp": {"expirationDate", "validUntil"},
		} {
			if _, signed := claims[claim]; !signed {
				continue
			}
			if !bodyHasAny(body, members) {
				return nil, memberErr(members[0])
			}
		}
		if _, signed := claims["sub"]; signed && !subjectHasID(body["credentialSubject"]) {
			return nil, memberErr("credentialSubject")
		}
	}

	return claims, nil
}

// BodyIsPresentation returns true when the body's type array contains
// "VerifiablePresentation". Exported so callers (e.g. verifyJWTProof) can
// pick the proof purpose from the same detection the binding check uses.
func BodyIsPresentation(body map[string]interface{}) bool {
	return bodyIsPresentation(body)
}

// bodyIsPresentation returns true when the body's type array contains
// "VerifiablePresentation".
func bodyIsPresentation(body map[string]interface{}) bool {
	switch t := body["type"].(type) {
	case []interface{}:
		for _, v := range t {
			if s, ok := v.(string); ok && s == "VerifiablePresentation" {
				return true
			}
		}
	case []string:
		for _, s := range t {
			if s == "VerifiablePresentation" {
				return true
			}
		}
	case string:
		return t == "VerifiablePresentation"
	}
	return false
}

// jwtSignedTime extracts the signed time from the JWT claims: iat first,
// else nbf. Returns the zero Time when neither is a valid integer.
func jwtSignedTime(claims map[string]interface{}) time.Time {
	for _, key := range []string{"iat", "nbf"} {
		if num, ok := claims[key].(float64); ok &&
			!math.IsNaN(num) && !math.IsInf(num, 0) && num == math.Trunc(num) {
			return time.Unix(int64(num), 0).UTC()
		}
	}
	return time.Time{}
}

// checkMovedField checks whether a body member absent from the vc claim is
// accounted for by the VC-JWT 1.1 moved-field table.
func checkMovedField(key string, bodyVal interface{}, claims map[string]interface{}) error {
	switch key {
	case "issuer":
		return checkMovedIssuer(bodyVal, claims)
	case "id":
		return checkStringClaim(key, bodyVal, claims, "jti")
	case "issuanceDate", "validFrom":
		return checkTimeClaim(key, bodyVal, claims, "nbf")
	case "expirationDate", "validUntil":
		return checkTimeClaim(key, bodyVal, claims, "exp")
	default:
		return memberErr(key)
	}
}

// checkMovedFieldVP checks whether a body member absent from the vp claim is
// accounted for by the VC-JWT 1.1 §6.3.2 VP moved-field table:
// holder ↔ iss, id ↔ jti (no date fields).
func checkMovedFieldVP(key string, bodyVal interface{}, claims map[string]interface{}) error {
	switch key {
	case "holder":
		return checkMovedHolder(bodyVal, claims)
	case "id":
		return checkStringClaim(key, bodyVal, claims, "jti")
	default:
		return memberErr(key)
	}
}

// checkMovedIssuer validates the issuer field against iss.
// A string issuer must equal iss. An object issuer must have only "id"
// equal to iss; additional members like "name" are unsigned.
func checkMovedIssuer(bodyVal interface{}, claims map[string]interface{}) error {
	iss, _ := claims["iss"].(string)
	if iss == "" {
		return memberErr("issuer")
	}
	switch v := bodyVal.(type) {
	case string:
		if v != iss {
			return memberErr("issuer")
		}
		return nil
	case map[string]interface{}:
		if len(v) != 1 {
			return memberErr("issuer")
		}
		id, _ := v["id"].(string)
		if id != iss {
			return memberErr("issuer")
		}
		return nil
	default:
		return memberErr("issuer")
	}
}

// checkMovedHolder validates the VP holder field against iss.
func checkMovedHolder(bodyVal interface{}, claims map[string]interface{}) error {
	iss, _ := claims["iss"].(string)
	if iss == "" {
		return memberErr("holder")
	}
	s, ok := bodyVal.(string)
	if !ok || s != iss {
		return memberErr("holder")
	}
	return nil
}

// checkSubjectIDMovedToSub handles the case where credentialSubject is present
// in both body and vc but they differ because the id field was moved to the sub
// JWT claim (VC-JWT 1.1 §6.3.1). When credentialSubject is an array, sub is
// the id of the first element; the other elements must match as-is.
func checkSubjectIDMovedToSub(bodyVal, vcVal interface{}, claims map[string]interface{}) error {
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return memberErr("credentialSubject")
	}

	switch bv := bodyVal.(type) {
	case map[string]interface{}:
		vv, ok := vcVal.(map[string]interface{})
		if !ok {
			return memberErr("credentialSubject")
		}
		return checkSingleSubjectID(bv, vv, sub)

	case []interface{}:
		va, ok := vcVal.([]interface{})
		if !ok || len(bv) != len(va) {
			return memberErr("credentialSubject")
		}
		if len(bv) == 0 {
			return memberErr("credentialSubject")
		}
		// First element: id may be moved to sub.
		bFirst, ok1 := bv[0].(map[string]interface{})
		vFirst, ok2 := va[0].(map[string]interface{})
		if !ok1 || !ok2 {
			return memberErr("credentialSubject")
		}
		if err := checkSingleSubjectID(bFirst, vFirst, sub); err != nil {
			return err
		}
		// Remaining elements must match exactly.
		for i := 1; i < len(bv); i++ {
			if !jsonDeepEqual(bv[i], va[i]) {
				return memberErr("credentialSubject")
			}
		}
		return nil

	default:
		return memberErr("credentialSubject")
	}
}

// checkSingleSubjectID verifies that a body subject object equals the vc subject
// object except for the id field, which must equal sub.
func checkSingleSubjectID(bodySubject, vcSubject map[string]interface{}, sub string) error {
	bodyID, hasBodyID := bodySubject["id"].(string)
	_, hasVCID := vcSubject["id"]
	if !hasBodyID || hasVCID {
		// If body has no id, or vc already has id, this isn't the moved-id case.
		return memberErr("credentialSubject")
	}
	if bodyID != sub {
		return memberErr("credentialSubject")
	}
	// Every other field in the body subject must match vc subject.
	if len(bodySubject)-1 != len(vcSubject) {
		return memberErr("credentialSubject")
	}
	for k, bv := range bodySubject {
		if k == "id" {
			continue
		}
		vv, ok := vcSubject[k]
		if !ok || !jsonDeepEqual(bv, vv) {
			return memberErr("credentialSubject")
		}
	}
	return nil
}

// checkStringClaim checks a string body member against a string JWT claim.
func checkStringClaim(key string, bodyVal interface{}, claims map[string]interface{}, claimKey string) error {
	bodyStr, ok := bodyVal.(string)
	if !ok {
		return memberErr(key)
	}
	claimVal, _ := claims[claimKey].(string)
	if bodyStr != claimVal {
		return memberErr(key)
	}
	return nil
}

// checkTimeClaim checks an RFC 3339 date string in the body against a
// numeric Unix timestamp JWT claim (nbf or exp).
func checkTimeClaim(key string, bodyVal interface{}, claims map[string]interface{}, claimKey string) error {
	dateStr, ok := bodyVal.(string)
	if !ok {
		return memberErr(key)
	}
	t, err := time.Parse(time.RFC3339, dateStr)
	if err != nil {
		return memberErr(key)
	}
	claimNum, ok := claims[claimKey].(float64)
	if !ok {
		return memberErr(key)
	}
	// A fractional, NaN, or Inf timestamp is not a valid second-precision
	// Unix time; refuse rather than silently truncating.
	if math.IsNaN(claimNum) || math.IsInf(claimNum, 0) || claimNum != math.Trunc(claimNum) {
		return memberErr(key)
	}
	if t.Unix() != int64(claimNum) {
		return memberErr(key)
	}
	return nil
}

// jsonDeepEqual compares two values by normalizing them through a JSON
// round-trip and then using reflect.DeepEqual. This ensures that values
// parsed from different JSON sources compare correctly regardless of
// concrete Go types (e.g. CredentialData vs map[string]interface{}).
func jsonDeepEqual(a, b interface{}) bool {
	aj, err := json.Marshal(a)
	if err != nil {
		return false
	}
	bj, err := json.Marshal(b)
	if err != nil {
		return false
	}
	var av, bv interface{}
	if err := json.Unmarshal(aj, &av); err != nil {
		return false
	}
	if err := json.Unmarshal(bj, &bv); err != nil {
		return false
	}
	return reflect.DeepEqual(av, bv)
}

func bindingErr(msg string) error {
	return fmt.Errorf("%s: %w", msg, ErrJwtProofBinding)
}

func memberErr(key string) error {
	quoted := key
	if len(quoted) > 64 {
		quoted = quoted[:64]
	}
	return fmt.Errorf("member %q not covered by JWT: %w", quoted, ErrJwtProofBinding)
}

// bodyHasAny returns true when the body contains at least one of the given keys.
func bodyHasAny(body map[string]interface{}, keys []string) bool {
	for _, k := range keys {
		if _, ok := body[k]; ok {
			return true
		}
	}
	return false
}

// subjectHasID reports whether the subject a signed sub stands for carries an
// "id": the object itself, or the first element of an array.
func subjectHasID(raw interface{}) bool {
	switch v := raw.(type) {
	case map[string]interface{}:
		_, ok := v["id"]
		return ok
	case []interface{}:
		// sub stands for the first subject: VC-JWT 1.1 moves that subject's id
		// into it, and checkSubjectIDMovedToSub compares it with the first
		// element only. An id on another subject must not stand in for it.
		if len(v) == 0 {
			return false
		}
		if m, ok := v[0].(map[string]interface{}); ok {
			_, hasID := m["id"]
			return hasID
		}
	}
	return false
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
