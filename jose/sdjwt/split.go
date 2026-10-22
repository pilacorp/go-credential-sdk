// Ported from sd-jwt-python (Apache-2.0), src/sd_jwt/common.py (_split,
// _parse_sd_jwt). See jose/NOTICE.

package sdjwt

import (
	"fmt"
	"strings"
)

// Split is Limits{}.Split.
func Split(compact string) (issuerJWT string, disclosures []string, kbJWT string, err error) {
	return Limits{}.Split(compact)
}

// Split separates <issuer JWT>~<D1>~…~<Dn>~<KB-JWT> (RFC 9901 section 4):
//   - input longer than l.MaxBytes is ErrTooLarge, before any parsing;
//   - no ~ at all is ErrMalformed (a plain JWT is not an SD-JWT);
//   - the first part must be a JWT of three non-empty dot-separated parts;
//   - the part after the last ~ is the KB-JWT, empty when there is none; when
//     present it must have three non-empty parts too, which also catches a
//     missing trailing ~ after the last disclosure;
//   - the parts in between are disclosures: an empty one (~~) or the same
//     one twice is ErrMalformed, more than l.MaxDisclosures is ErrTooLarge.
//
// Signatures, base64url and JSON are not checked here.
func (l Limits) Split(compact string) (issuerJWT string, disclosures []string, kbJWT string, err error) {
	l = l.withDefaults()
	if len(compact) > l.MaxBytes {
		return "", nil, "", fmt.Errorf("%w: SD-JWT of %d bytes, at most %d", ErrTooLarge, len(compact), l.MaxBytes)
	}
	tildes := strings.Count(compact, "~")
	if tildes == 0 {
		return "", nil, "", fmt.Errorf("%w: no ~ separator", ErrMalformed)
	}
	if tildes-1 > l.MaxDisclosures {
		return "", nil, "", fmt.Errorf("%w: %d disclosures, at most %d", ErrTooLarge, tildes-1, l.MaxDisclosures)
	}
	parts := strings.Split(compact, "~")
	issuerJWT, kbJWT = parts[0], parts[len(parts)-1]
	if !isCompactJWS(issuerJWT) {
		return "", nil, "", fmt.Errorf("%w: issuer-signed JWT is not three non-empty dot-separated parts", ErrMalformed)
	}
	if kbJWT != "" && !isCompactJWS(kbJWT) {
		return "", nil, "", fmt.Errorf("%w: the part after the last ~ is not a JWT (missing trailing ~?)", ErrMalformed)
	}
	disclosures = parts[1 : len(parts)-1]
	seen := make(map[string]bool, len(disclosures))
	for i, d := range disclosures {
		if d == "" {
			return "", nil, "", fmt.Errorf("%w: empty disclosure at position %d (~~)", ErrMalformed, i+1)
		}
		if seen[d] {
			return "", nil, "", fmt.Errorf("%w: disclosure at position %d given twice", ErrMalformed, i+1)
		}
		seen[d] = true
	}
	return issuerJWT, disclosures, kbJWT, nil
}

func isCompactJWS(s string) bool {
	parts := strings.Split(s, ".")
	return len(parts) == 3 && parts[0] != "" && parts[1] != "" && parts[2] != ""
}
