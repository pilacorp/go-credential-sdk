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
		// Only treat as holder binding JWT if:
		// 1. This is the last segment AND
		// 2. It looks like a JWT AND
		// 3. There is a ~ before this segment (i.e., not the first disclosure)
		//    This ensures "issuer~jwt-like" (no ~ before last) is treated as disclosure
		//    but "issuer~D~JWT" (has ~ before last) is treated as holder binding.
		// Note: KB-JWT is not verified - just skipped if detected.
		if i == len(parts)-1 && isJWT(seg) && i > 1 {
			break
		}
		disclosures = append(disclosures, seg)
	}

	// Decode disclosures for easy access
	decodedDisclosures, err := parseDisclosures(disclosures)
	if err != nil {
		return nil, fmt.Errorf("failed to decode disclosures: %w", err)
	}

	return &ParsedSDJWT{
		BaseJWT:            issuer,
		Disclosures:        disclosures,
		DecodedDisclosures: decodedDisclosures,
	}, nil
}

// BuildSDJWTPresentation builds an SD-JWT presentation string from the issuer-signed JWT
// and a subset of disclosure strings.
func BuildSDJWTPresentation(issuerSignedJWT string, selectedDisclosures []string) string {
	var sb strings.Builder
	sb.WriteString(issuerSignedJWT)
	hasDisclosure := false
	for _, sel := range selectedDisclosures {
		if sel == "" {
			continue
		}
		sb.WriteString("~")
		sb.WriteString(sel)
		hasDisclosure = true
	}
	if hasDisclosure {
		sb.WriteString("~")
	}
	return sb.String()
}

// parseDisclosures parses a slice of disclosure strings into DecodedDisclosure.
// Used by Holders to understand what each disclosure contains.
func parseDisclosures(disclosures []string) ([]DecodedDisclosure, error) {
	result := make([]DecodedDisclosure, 0, len(disclosures))

	for _, disc := range disclosures {
		if disc == "" {
			continue
		}

		info, err := parseDisclosure(disc)
		if err != nil {
			return nil, err
		}

		// Map internal info to public DecodedDisclosure
		dec := DecodedDisclosure{
			Disclosure:  disc,
			Salt:        info.salt,
			FieldName:   info.objectField,
			Value:       info.value,
			IsArrayElem: info.isArrayElem,
		}
		result = append(result, dec)
	}

	return result, nil
}

// parseDisclosure parses a single disclosure string into internal disclosureInfo.
// This is the core parsing function used by both Reconstruct and parseDisclosures.
func parseDisclosure(disc string) (disclosureInfo, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(disc)
	if err != nil {
		return disclosureInfo{}, fmt.Errorf("failed to decode disclosure %q: %w", disc, err)
	}

	var arr []interface{}
	if err := json.Unmarshal(decoded, &arr); err != nil {
		return disclosureInfo{}, fmt.Errorf("failed to unmarshal disclosure: %w", err)
	}

	// Validate disclosure structure: must have 2 or 3 elements
	if len(arr) != 2 && len(arr) != 3 {
		return disclosureInfo{}, fmt.Errorf("invalid disclosure structure: expected 2 or 3 elements, got %d", len(arr))
	}

	info := disclosureInfo{
		raw:   disc,
		array: arr,
	}

	switch len(arr) {
	case 3:
		// Format: [salt, name, value] - object field
		// Validate salt is string
		if _, ok := arr[0].(string); !ok {
			return disclosureInfo{}, fmt.Errorf("disclosure salt must be a string")
		}
		info.salt = arr[0].(string)
		if name, ok := arr[1].(string); ok {
			info.objectField = name
			info.value = arr[2]
			info.isArrayElem = false
		} else {
			return disclosureInfo{}, fmt.Errorf("disclosure field name must be a string")
		}
	case 2:
		// Format: [salt, value] - array element
		// Validate salt is string
		if _, ok := arr[0].(string); !ok {
			return disclosureInfo{}, fmt.Errorf("disclosure salt must be a string")
		}
		info.salt = arr[0].(string)
		info.value = arr[1]
		info.isArrayElem = true
	}

	return info, nil
}

var jwtRegex = regexp.MustCompile(`^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+(\.[A-Za-z0-9\-_]+)?$`)

// isJWT performs a simple regex check for JWT format: header.payload[.signature].
func isJWT(s string) bool {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, ".")
	return jwtRegex.MatchString(s)
}

// hashDisclosure computes digest_b64u(sdAlg, D) where D is a base64url disclosure string.
func hashDisclosure(sdAlg, disclosure string) (string, error) {
	switch sdAlg {
	case AlgSHA256:
		sum := sha256.Sum256([]byte(disclosure))
		return base64.RawURLEncoding.EncodeToString(sum[:]), nil
	case AlgSHA384:
		sum := sha512.Sum384([]byte(disclosure))
		return base64.RawURLEncoding.EncodeToString(sum[:]), nil
	case AlgSHA512:
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
