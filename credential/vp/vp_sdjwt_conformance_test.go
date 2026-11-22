package vp_test

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/pilacorp/go-credential-sdk/credential/vp"
)

// --- Finding 1: VP must reject reserved disclosure names and remove undisclosed array elements ---

// buildVPSDJWTToken constructs a raw vp+sd-jwt token from header, payload and
// disclosures for testing parse-side rules. The token is unsigned (fake sig).
func buildVPSDJWTToken(t *testing.T, header, payload map[string]interface{}, disclosures []string) string {
	t.Helper()
	hBytes, _ := json.Marshal(header)
	pBytes, _ := json.Marshal(payload)
	token := base64.RawURLEncoding.EncodeToString(hBytes) + "." +
		base64.RawURLEncoding.EncodeToString(pBytes) + ".fake-sig"
	for _, d := range disclosures {
		token += "~" + d
	}
	token += "~"
	return token
}

// encodeDisclosure encodes a JSON array as a base64url disclosure string.
func encodeDisclosure(t *testing.T, arr []interface{}) string {
	t.Helper()
	b, err := json.Marshal(arr)
	if err != nil {
		t.Fatalf("marshal disclosure: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func digestSHA256(t *testing.T, disc string) string {
	t.Helper()
	sum := sha256.Sum256([]byte(disc))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func digestSHA384(t *testing.T, disc string) string {
	t.Helper()
	sum := sha512.Sum384([]byte(disc))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// F1a: VP sha-256 path must reject a disclosure whose claim name is "_sd".
func TestVPSDJWT_ReservedName_SD_SHA256(t *testing.T) {
	disc := encodeDisclosure(t, []interface{}{"salt1", "_sd", "evil"})

	header := map[string]interface{}{
		"typ": "vp+sd-jwt",
		"alg": "ES256",
		"kid": "did:example:holder#key-1",
	}
	payload := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":     []interface{}{"VerifiablePresentation"},
		"holder":   "did:example:holder",
		"_sd_alg":  "sha-256",
		"custom": map[string]interface{}{
			"_sd": []interface{}{digestSHA256(t, disc)},
		},
	}

	token := buildVPSDJWTToken(t, header, payload, []string{disc})
	_, err := vp.ParseJOSEPresentation(token)
	if err == nil {
		t.Fatal("expected error for disclosure with reserved name _sd")
	}
	if !strings.Contains(err.Error(), "_sd") {
		t.Fatalf("error should mention _sd: %v", err)
	}
}

// F1b: VP sha-384 path must reject a disclosure whose claim name is "...".
func TestVPSDJWT_ReservedName_Ellipsis_SHA384(t *testing.T) {
	disc := encodeDisclosure(t, []interface{}{"salt2", "...", "evil"})

	header := map[string]interface{}{
		"typ": "vp+sd-jwt",
		"alg": "ES256",
		"kid": "did:example:holder#key-1",
	}
	payload := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":     []interface{}{"VerifiablePresentation"},
		"holder":   "did:example:holder",
		"_sd_alg":  "sha-384",
		"custom": map[string]interface{}{
			"_sd": []interface{}{digestSHA384(t, disc)},
		},
	}

	token := buildVPSDJWTToken(t, header, payload, []string{disc})
	_, err := vp.ParseJOSEPresentation(token)
	if err == nil {
		t.Fatal("expected error for disclosure with reserved name ...")
	}
	if !strings.Contains(err.Error(), "reserved") || !strings.Contains(err.Error(), "...") {
		t.Fatalf("error should mention reserved name ...: %v", err)
	}
}

// --- Finding 3: typ comparison must be case-insensitive ---

// F3a: VP+SD-JWT (uppercase) with disclosures must be accepted as SD-JWT.
func TestVPSDJWT_CaseInsensitiveTyp_Uppercase(t *testing.T) {
	header := map[string]interface{}{
		"typ": "VP+SD-JWT",
		"alg": "ES256",
		"kid": "did:example:holder#key-1",
	}
	payload := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":     []interface{}{"VerifiablePresentation"},
		"holder":   "did:example:holder",
		"_sd_alg":  "sha-256",
	}
	token := buildVPSDJWTToken(t, header, payload, nil)

	// Should not fail because of typ mismatch. It may fail on other things
	// (unsigned, etc.) but NOT on "does not match the SD-JWT format".
	_, err := vp.ParseJOSEPresentation(token)
	if err != nil && strings.Contains(err.Error(), "does not match the SD-JWT format") {
		t.Fatalf("uppercase VP+SD-JWT should be recognized as SD-JWT: %v", err)
	}
}

// F3b: application/vp+sd-jwt with disclosures must be accepted as SD-JWT.
func TestVPSDJWT_CaseInsensitiveTyp_ApplicationPrefix(t *testing.T) {
	header := map[string]interface{}{
		"typ": "application/vp+sd-jwt",
		"alg": "ES256",
		"kid": "did:example:holder#key-1",
	}
	payload := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":     []interface{}{"VerifiablePresentation"},
		"holder":   "did:example:holder",
		"_sd_alg":  "sha-256",
	}
	token := buildVPSDJWTToken(t, header, payload, nil)

	_, err := vp.ParseJOSEPresentation(token)
	if err != nil && strings.Contains(err.Error(), "does not match the SD-JWT format") {
		t.Fatalf("application/vp+sd-jwt should be recognized as SD-JWT: %v", err)
	}
}
