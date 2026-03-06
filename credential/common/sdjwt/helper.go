package sdjwt

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// DecodedDisclosure represents a decoded disclosure that Holder can use to understand what it contains.
type DecodedDisclosure struct {
	Disclosure  string      // Original disclosure string
	Salt        string      // The salt value
	FieldName   string      // The field name (for object field disclosures)
	Value       interface{} // The value (for object field: claim value, for array: element value)
	IsArrayElem bool        // True if this is an array element disclosure
}

// IsSDJWT checks whether the input string looks like an SD-JWT.
func IsSDJWT(raw string) bool {
	if raw == "" {
		return false
	}

	s := strings.TrimSpace(strings.Trim(raw, "\""))
	if !strings.Contains(s, "~") {
		return false
	}

	parts := strings.SplitN(s, "~", 2)
	if len(parts) < 2 {
		return false
	}

	return isJWT(parts[0])
}

// Parse splits an SD-JWT into issuer-signed JWT and its disclosures.
// It also decodes all disclosures and populates DecodedDisclosures for easy access by Holders.
func Parse(raw string) (*ParsedSDJWT, error) {
	if !IsSDJWT(raw) {
		return nil, fmt.Errorf("invalid SD-JWT format")
	}

	s := strings.TrimSpace(strings.Trim(raw, "\""))
	parts := strings.Split(s, "~")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid SD-JWT: missing disclosures or terminator")
	}

	issuer := parts[0]
	var disclosures []string
	for i := 1; i < len(parts); i++ {
		seg := strings.TrimSpace(parts[i])
		if seg == "" {
			continue
		}
		if i == len(parts)-1 && isJWT(seg) {
			break
		}
		disclosures = append(disclosures, seg)
	}

	// Decode disclosures for easy access
	decodedDisclosures, err := decodeDisclosures(disclosures)
	if err != nil {
		return nil, fmt.Errorf("failed to decode disclosures: %w", err)
	}

	return &ParsedSDJWT{
		BaseJWT:            issuer,
		Disclosures:        disclosures,
		DecodedDisclosures: decodedDisclosures,
	}, nil
}

// decodeDisclosures decodes a slice of disclosure strings.
func decodeDisclosures(disclosures []string) ([]DecodedDisclosure, error) {
	result := make([]DecodedDisclosure, 0, len(disclosures))

	for _, D := range disclosures {
		if D == "" {
			continue
		}

		decoded, err := base64.RawURLEncoding.DecodeString(D)
		if err != nil {
			return nil, fmt.Errorf("failed to decode disclosure %q: %w", D, err)
		}

		var arr []interface{}
		if err := json.Unmarshal(decoded, &arr); err != nil {
			return nil, fmt.Errorf("failed to unmarshal disclosure: %w", err)
		}

		if len(arr) != 2 && len(arr) != 3 {
			return nil, fmt.Errorf("invalid disclosure: expected 2 or 3 elements, got %d", len(arr))
		}

		dec := DecodedDisclosure{
			Disclosure: D,
		}

		switch len(arr) {
		case 3:
			salt, ok := arr[0].(string)
			if !ok {
				return nil, fmt.Errorf("disclosure salt must be string")
			}
			dec.Salt = salt

			name, ok := arr[1].(string)
			if !ok {
				return nil, fmt.Errorf("disclosure field name must be string")
			}
			dec.FieldName = name
			dec.Value = arr[2]
			dec.IsArrayElem = false

		case 2:
			salt, ok := arr[0].(string)
			if !ok {
				return nil, fmt.Errorf("disclosure salt must be string")
			}
			dec.Salt = salt
			dec.Value = arr[1]
			dec.IsArrayElem = true
		}

		result = append(result, dec)
	}

	return result, nil
}

// BuildSDJWTPresentation builds an SD-JWT presentation string from the issuer-signed JWT
// and a subset of disclosure strings.
func BuildSDJWTPresentation(issuerSignedJWT string, selectedDisclosures []string) string {
	var sb strings.Builder
	sb.WriteString(issuerSignedJWT)
	for _, d := range selectedDisclosures {
		if d == "" {
			continue
		}
		sb.WriteString("~")
		sb.WriteString(d)
	}
	sb.WriteString("~")
	return sb.String()
}

// isJWT performs a simple regex check for JWT format: header.payload[.signature].
func isJWT(s string) bool {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, ".")
	const re = `^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+(\.[A-Za-z0-9\-_]+)?$`
	match, _ := regexp.MatchString(re, s)
	return match
}

// hashDisclosure computes digest_b64u(sdAlg, D) where D is a base64url disclosure string.
func hashDisclosure(sdAlg, disclosure string) (string, error) {
	switch strings.ToLower(sdAlg) {
	case "sha-256", "sha256":
		sum := sha256.Sum256([]byte(disclosure))
		return base64.RawURLEncoding.EncodeToString(sum[:]), nil
	case "sha-384", "sha384":
		sum := sha512.Sum384([]byte(disclosure))
		return base64.RawURLEncoding.EncodeToString(sum[:]), nil
	case "sha-512", "sha512":
		sum := sha512.Sum512([]byte(disclosure))
		return base64.RawURLEncoding.EncodeToString(sum[:]), nil
	default:
		return "", fmt.Errorf("unsupported sd_alg %q", sdAlg)
	}
}

// randomSalt generates a random salt string (base64url-encoded).
func randomSalt() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf[:]), nil
}
