package jwe

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

const (
	// Algorithm is the "alg" of every message: the key both parties hold is
	// the content encryption key itself (RFC 7518 §4.5).
	Algorithm = "dir"
	// Encryption is the "enc" of every message (RFC 7518 §5.3).
	Encryption = "A256GCM"
	// ProtectedHeader is the encoded protected header of every message,
	// BASE64URL(UTF8(`{"alg":"dir","enc":"A256GCM"}`)). Its ASCII bytes are
	// the additional authenticated data (RFC 7516 §5.1 step 14).
	ProtectedHeader = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0"
)

// JWE is the flattened JWE JSON serialization (RFC 7516 §7.2.2) of a message
// with no encrypted key, as "dir" produces.
type JWE struct {
	Protected  string `json:"protected"`
	IV         string `json:"iv"`
	Ciphertext string `json:"ciphertext"`
	Tag        string `json:"tag"`
}

func base64url(input []byte) string {
	return base64.RawURLEncoding.EncodeToString(input)
}

// BuildJWE returns the flattened JWE JSON serialization of a message whose
// encoded protected header is protected.
func BuildJWE(protected string, iv, ciphertext, tag []byte) (string, error) {
	result, err := json.MarshalIndent(JWE{
		Protected:  protected,
		IV:         base64url(iv),
		Ciphertext: base64url(ciphertext),
		Tag:        base64url(tag),
	}, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal JWE: %w", err)
	}
	return string(result), nil
}
