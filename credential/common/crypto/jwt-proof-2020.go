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
// directly in the vc/vp claim or via the VC-JWT 1.1 moved-field mapping. A body
// equal to what did-jwt-vc decodes from the JWT is accepted as a whole (see
// jwt-proof-2020-didjwtvc.go).
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

	if err := checkMappedBody(body, container, claims, isVP); err != nil {
		// A body that did-jwt-vc decoded from this JWT is the other accepted
		// form; it is tried second so the common mapped body pays nothing.
		if bodyIsDidJwtVcForm(claims, body, isVP) {
			return claims, nil
		}
		return nil, err
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
