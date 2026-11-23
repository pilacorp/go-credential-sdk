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

	josesdjwt "github.com/pilacorp/go-credential-sdk/jose/sdjwt"
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
		// A trailing JWT after the disclosures is a key binding JWT: the holder
		// proving it holds the key the credential was issued to, over a nonce
		// and audience the verifier named.
		//
		// Skipping it silently was worse than not supporting it. A verifier that
		// asked for holder binding would get a nil error back from a token whose
		// binding nothing checked, and the KB-JWT also gave the token a second
		// byte form under the same Hash(). Refused until it is verified.
		if i == len(parts)-1 && isJWT(seg) && i > 1 {
			return nil, fmt.Errorf(
				"SD-JWT carries a key binding JWT, which this SDK does not verify yet; present the credential without it")
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
//
// The trailing "~" is written even when nothing is selected, because that is
// what makes the result an SD-JWT: draft-ietf-oauth-selective-disclosure-jwt § 4
// terminates the combined format with it, and a holder revealing nothing is
// still presenting an SD-JWT. Omitting it returned a bare JWT, which IsSDJWT
// does not recognise — so the digests were never folded out of the payload and
// a presentation whose header says vc+sd-jwt was enveloped as vc+jwt.
//
// Callers must not hand a plain JWT here; Present checks that the credential
// has disclosures before calling.
func BuildSDJWTPresentation(issuerSignedJWT string, selectedDisclosures []string) string {
	var sb strings.Builder
	sb.WriteString(issuerSignedJWT)
	for _, sel := range selectedDisclosures {
		if sel == "" {
			continue
		}
		sb.WriteString("~")
		sb.WriteString(sel)
	}
	sb.WriteString("~")

	return sb.String()
}

// DecodeDisclosures decodes disclosure strings into DecodedDisclosure so a
// Holder can inspect each field name and value before selecting which to
// present. Each disclosure is decoded through jose/sdjwt.ParseDisclosure, which
// rejects the reserved claim names "...", "_sd" and "_sd_alg" (RFC 9901
// section 4.2.1, section 7.1 step 3c.ii.2). The sha-256 digest that
// ParseDisclosure computes is not exposed in DecodedDisclosure; callers that
// need a digest under a different algorithm (sha-384, sha-512) compute it
// themselves from DecodedDisclosure.Disclosure.
func DecodeDisclosures(disclosures []string) ([]DecodedDisclosure, error) {
	result := make([]DecodedDisclosure, 0, len(disclosures))
	for _, disc := range disclosures {
		if disc == "" {
			continue
		}
		p, err := josesdjwt.ParseDisclosure(disc)
		if err != nil {
			return nil, fmt.Errorf("decode disclosure: %w", err)
		}
		dec := DecodedDisclosure{
			Disclosure:  disc,
			Salt:        p.Salt,
			FieldName:   p.Name,
			Value:       p.Value,
			IsArrayElem: p.ArrayElement,
		}
		result = append(result, dec)
	}
	return result, nil
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

// RecreatePayload returns the claims of an SD-JWT payload with the
// disclosures put back, without changing payload. Every disclosure is first
// validated through jose/sdjwt.ParseDisclosure, which applies RFC 9901
// section 7.1: the reserved claim names "_sd", "..." and "_sd_alg" are
// refused, and the base64url encoding must be strict. A sha-256 payload goes
// through jose/sdjwt.Recreate (which also removes undisclosed array elements
// and refuses duplicate digests); sha-384 and sha-512 go through Reconstruct,
// which also removes undisclosed array elements.
//
// Both the VC and VP parse paths call this, so a credential or presentation
// that signs is read by the same rules when it is parsed.
func RecreatePayload(payload map[string]interface{}, disclosures []string) (map[string]interface{}, error) {
	// ParseDisclosure reads a disclosure's form and refuses the reserved claim
	// names (RFC 9901 section 4.2.1) whatever hash the payload uses.
	parsed := make([]josesdjwt.Disclosure, len(disclosures))
	for i, d := range disclosures {
		p, err := josesdjwt.ParseDisclosure(d)
		if err != nil {
			return nil, fmt.Errorf("failed to parse disclosure: %w", err)
		}
		parsed[i] = p
	}
	if alg, _ := payload["_sd_alg"].(string); alg == AlgSHA384 || alg == AlgSHA512 {
		// module jose recreates sha-256 only. Check the payload's shape by its
		// rules first (RFC 9901 section 4.1 rule 7, 4.1.1, 4.2.4.2), on a copy
		// labelled sha-256 with no disclosures, so every hash refuses what
		// sha-256 refuses; then put the disclosures back with Reconstruct.
		shape := make(map[string]interface{}, len(payload))
		for k, v := range payload {
			shape[k] = v
		}
		shape["_sd_alg"] = DefaultHashAlgorithm
		if _, err := josesdjwt.Recreate(shape, nil); err != nil {
			return nil, err
		}
		return Reconstruct(payload, disclosures, true)
	}
	// Any other _sd_alg, sha-256 or unknown, goes to module jose, which
	// refuses an algorithm it does not implement.
	recreated, err := josesdjwt.Recreate(payload, parsed)
	if err != nil {
		return nil, err
	}
	return recreated.Claims, nil
}
