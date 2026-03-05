package sdjwt

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
)

// IsSDJWT checks whether the input string looks like an SD-JWT.
// It only validates the format:
//   - contains at least one '~'
//   - the part before the first '~' is a JWT (header.payload[.signature])
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
// It assumes the input has already been validated by IsSDJWT.
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
		// If this is the last segment and it looks like a JWT, treat it as KB-JWT and stop.
		if i == len(parts)-1 && isJWT(seg) {
			break
		}
		disclosures = append(disclosures, seg)
	}

	return &ParsedSDJWT{
		Raw:             s,
		BaseJWT: issuer,
		Disclosures:     disclosures,
	}, nil
}

// isJWT performs a simple regex check for JWT format: header.payload[.signature].
func isJWT(s string) bool {
	s = strings.TrimSpace(s)

	// Allow optional trailing dot for unsigned-but-3-part forms (header.payload.).
	s = strings.TrimSuffix(s, ".")

	// Allow 2 or 3 non-empty segments: header.payload[.signature].
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
