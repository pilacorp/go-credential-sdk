package didcomm

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/pilacorp/go-credential-sdk/didcomm/jwe"
)

// JWE is the flattened JWE JSON serialization (RFC 7516 §7.2.2) Encrypt
// writes and DecryptJWE reads.
type JWE = jwe.JWE

const (
	// keySize is the A256GCM key length (RFC 7518 §5.3).
	keySize = 32
	// tagSize is the A256GCM authentication tag length (RFC 7518 §5.3).
	tagSize = 16
)

// unsupportedMembers are JWE JSON members this package does not implement.
// Each would change the key or the AAD (RFC 7516 §5.2 steps 8 and 14), so a
// message carrying one is refused rather than read without it. With "dir"
// the encrypted key is empty, and RFC 7516 §7.2.1 then requires
// encrypted_key to be absent.
var unsupportedMembers = []string{"encrypted_key", "aad", "unprotected", "header", "recipients"}

// base64urlDecode decodes unpadded base64url with no other characters
// (RFC 7515 §2). encoding/base64 skips CR and LF, so they are refused first.
func base64urlDecode(input string) ([]byte, error) {
	if strings.ContainsAny(input, "\r\n") {
		return nil, errors.New("illegal line break")
	}
	return base64.RawURLEncoding.Strict().DecodeString(input)
}

// DecryptJWE decrypts a message Encrypt wrote, following RFC 7516 §5.2: a
// flattened JWE JSON serialization whose protected header has "alg" "dir"
// and "enc" "A256GCM", no "crit" and no "zip". sharedKey must be the 32
// bytes GetFromKeys returns.
func DecryptJWE(jweStr string, sharedKey []byte) (string, error) {
	// Into a map: member names are case-sensitive, and encoding/json would
	// fill a struct field from "Tag" or "TAG" too.
	var members map[string]json.RawMessage
	if err := json.Unmarshal([]byte(jweStr), &members); err != nil {
		return "", fmt.Errorf("unmarshal error: %w", err)
	}
	for _, name := range unsupportedMembers {
		if _, ok := members[name]; ok {
			return "", fmt.Errorf("unsupported JWE member %q", name)
		}
	}

	protected, err := stringMember(members, "protected")
	if err != nil {
		return "", err
	}
	if err := checkProtectedHeader(protected); err != nil {
		return "", err
	}

	if len(sharedKey) != keySize {
		return "", fmt.Errorf("invalid key size: got %d bytes, want %d for %s", len(sharedKey), keySize, jwe.Encryption)
	}
	block, err := aes.NewCipher(sharedKey)
	if err != nil {
		return "", fmt.Errorf("aes new cipher error: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("aes new gcm error: %w", err)
	}

	iv, err := decodeMember(members, "iv")
	if err != nil {
		return "", err
	}
	if len(iv) != gcm.NonceSize() {
		return "", fmt.Errorf("invalid nonce size: got %d, want %d", len(iv), gcm.NonceSize())
	}
	ciphertext, err := decodeMember(members, "ciphertext")
	if err != nil {
		return "", err
	}
	tag, err := decodeMember(members, "tag")
	if err != nil {
		return "", err
	}
	if len(tag) != tagSize {
		return "", fmt.Errorf("invalid tag size: got %d bytes, want %d", len(tag), tagSize)
	}

	sealed := make([]byte, 0, len(ciphertext)+len(tag))
	sealed = append(append(sealed, ciphertext...), tag...)
	plaintext, err := gcm.Open(nil, iv, sealed, []byte(protected))
	if err != nil {
		return "", fmt.Errorf("decryption failed: %w", err)
	}

	return string(plaintext), nil
}

// checkProtectedHeader decodes the protected header and refuses any header
// but {"alg":"dir","enc":"A256GCM"} with optional parameters this package
// can ignore (RFC 7516 §5.2 steps 2-5). Header parameter names are
// case-sensitive.
func checkProtectedHeader(protected string) error {
	if protected == "" {
		return errors.New(`missing "protected" header`)
	}
	raw, err := base64urlDecode(protected)
	if err != nil {
		return fmt.Errorf("base64url decode protected header: %w", err)
	}
	if !utf8.Valid(raw) {
		return errors.New("protected header is not valid UTF-8")
	}
	var header map[string]json.RawMessage
	if err := json.Unmarshal(raw, &header); err != nil || header == nil {
		return errors.New("protected header is not a JSON object")
	}

	// RFC 7515 §4.1.11: every extension "crit" lists must be understood,
	// and this package understands none.
	if _, ok := header["crit"]; ok {
		return errors.New(`unsupported "crit" header parameter`)
	}
	// RFC 7516 §4.1.3: compressed plaintext is not supported.
	if _, ok := header["zip"]; ok {
		return errors.New(`unsupported "zip" header parameter`)
	}
	for _, p := range []struct{ name, want string }{
		{"alg", jwe.Algorithm},
		{"enc", jwe.Encryption},
	} {
		var got string
		v, ok := header[p.name]
		if !ok || json.Unmarshal(v, &got) != nil || got != p.want {
			return fmt.Errorf("unsupported %q header parameter: want %q", p.name, p.want)
		}
	}

	return nil
}

func stringMember(members map[string]json.RawMessage, name string) (string, error) {
	v, ok := members[name]
	if !ok {
		return "", fmt.Errorf("missing JWE member %q", name)
	}
	var s string
	if err := json.Unmarshal(v, &s); err != nil {
		return "", fmt.Errorf("JWE member %q is not a string", name)
	}
	return s, nil
}

func decodeMember(members map[string]json.RawMessage, name string) ([]byte, error) {
	s, err := stringMember(members, name)
	if err != nil {
		return nil, err
	}
	b, err := base64urlDecode(s)
	if err != nil {
		return nil, fmt.Errorf("base64url decode %s: %w", name, err)
	}
	return b, nil
}
