package didcomm

import (
	"encoding/json"
	"strings"
	"testing"
)

// mustJWE builds a JWE JSON string with the given raw base64url field values.
func mustJWE(iv, ciphertext, tag string) string {
	j := JWE{
		Protected:  "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0", // {"alg":"dir","enc":"A256GCM"}
		IV:         iv,
		Ciphertext: ciphertext,
		Tag:        tag,
	}
	b, _ := json.Marshal(j)
	return string(b)
}

func TestDecryptJWE_MalformedInput(t *testing.T) {
	// 32-byte AES key (valid for AES-256)
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	tests := []struct {
		name   string
		jwe    string
		errSub string // case-insensitive substring expected in the error
	}{
		{
			name:   "not JSON",
			jwe:    "this is not json",
			errSub: "unmarshal",
		},
		{
			name:   "empty string",
			jwe:    "",
			errSub: "unmarshal",
		},
		{
			name:   "invalid base64 in IV",
			jwe:    mustJWE("!!bad!!", "AAAA", "AAAA"),
			errSub: "iv",
		},
		{
			name:   "invalid base64 in ciphertext",
			jwe:    mustJWE("AAAAAAAAAAAAAAAA", "!!bad!!", "AAAA"),
			errSub: "ciphertext",
		},
		{
			name:   "invalid base64 in tag",
			jwe:    mustJWE("AAAAAAAAAAAAAAAA", "AAAA", "!!bad!!"),
			errSub: "tag",
		},
		{
			name:   "IV wrong nonce size (6 bytes instead of 12)",
			jwe:    mustJWE("AAAAAAAA", "AAAA", "AAAA"),
			errSub: "nonce",
		},
		{
			name:   "empty IV",
			jwe:    mustJWE("", "AAAA", "AAAA"),
			errSub: "nonce",
		},
		{
			name:   "all fields empty strings",
			jwe:    mustJWE("", "", ""),
			errSub: "nonce",
		},
		{
			// Valid structure but wrong data — decryption must fail, not panic.
			// 16 base64url chars = 12 bytes (valid nonce), 8 chars = 6 bytes ciphertext,
			// 22 chars ≈ 16 bytes tag.
			name:   "tampered ciphertext and tag",
			jwe:    mustJWE("AAAAAAAAAAAAAAAA", "AAAAAAAA", "AAAAAAAAAAAAAAAAAAAAAA"),
			errSub: "decryption failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := DecryptJWE(tt.jwe, key)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil (result: %q)", tt.errSub, result)
			}
			if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tt.errSub)) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.errSub)
			}
		})
	}
}

func TestDecryptJWE_RoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	original := `{"hello":"world"}`
	jweStr, err := Encrypt(key, original)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	got, err := DecryptJWE(jweStr, key)
	if err != nil {
		t.Fatalf("DecryptJWE failed: %v", err)
	}
	if got != original {
		t.Errorf("round-trip mismatch: got %q, want %q", got, original)
	}
}
