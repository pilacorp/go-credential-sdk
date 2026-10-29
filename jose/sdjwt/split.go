// Ported from sd-jwt-python (Apache-2.0), src/sd_jwt/common.py (_split,
// _parse_sd_jwt). See jose/NOTICE.

package sdjwt

import (
	"fmt"
	"strings"

	"github.com/pilacorp/go-credential-sdk/jose"
)

// Split separates <Issuer-signed JWT>~<D.1>~…~<D.N>~<KB-JWT> (RFC 9901 §4).
// Every error wraps jose.ErrMalformed:
//   - input over 1 MiB (1 << 20 bytes), before any parsing;
//   - no ~ at all: a plain JWT is not an SD-JWT;
//   - a first part that is not three non-empty dot-separated parts;
//   - a last part that is neither empty (no KB-JWT) nor three non-empty
//     dot-separated parts, which also catches a missing trailing ~ (§4: the
//     final ~ "MUST NOT be omitted");
//   - an empty disclosure (~~), the same disclosure twice (§4: a Holder MUST
//     NOT send a Disclosure more than once), or more than 1000 disclosures.
//
// Signatures, base64url and JSON are not checked here.
func Split(compact string) (issuerJWT string, disclosures []string, kbJWT string, err error) {
	if len(compact) > maxBytes {
		return "", nil, "", fmt.Errorf("%w: sdjwt: SD-JWT of %d bytes, at most %d", jose.ErrMalformed, len(compact), maxBytes)
	}
	tildes := strings.Count(compact, "~")
	if tildes == 0 {
		return "", nil, "", fmt.Errorf("%w: sdjwt: no ~ separator", jose.ErrMalformed)
	}
	// Counted before strings.Split, so a megabyte of ~ is refused without
	// allocating a million strings.
	if tildes-1 > maxDisclosures {
		return "", nil, "", fmt.Errorf("%w: sdjwt: %d disclosures, at most %d", jose.ErrMalformed, tildes-1, maxDisclosures)
	}
	parts := strings.Split(compact, "~")
	issuerJWT, kbJWT = parts[0], parts[len(parts)-1]
	if !isCompactJWS(issuerJWT) {
		return "", nil, "", fmt.Errorf("%w: sdjwt: the Issuer-signed JWT is not three non-empty dot-separated parts", jose.ErrMalformed)
	}
	if kbJWT != "" && !isCompactJWS(kbJWT) {
		return "", nil, "", fmt.Errorf("%w: sdjwt: the part after the last ~ is not a JWT (missing trailing ~?)", jose.ErrMalformed)
	}
	disclosures = parts[1 : len(parts)-1]
	seen := make(map[string]bool, len(disclosures))
	for i, d := range disclosures {
		if d == "" {
			return "", nil, "", fmt.Errorf("%w: sdjwt: empty disclosure at position %d (~~)", jose.ErrMalformed, i+1)
		}
		if seen[d] {
			return "", nil, "", fmt.Errorf("%w: sdjwt: disclosure at position %d given twice", jose.ErrMalformed, i+1)
		}
		seen[d] = true
	}
	return issuerJWT, disclosures, kbJWT, nil
}

func isCompactJWS(s string) bool {
	header, rest, ok1 := strings.Cut(s, ".")
	payload, sig, ok2 := strings.Cut(rest, ".")
	return ok1 && ok2 && header != "" && payload != "" && sig != "" && !strings.Contains(sig, ".")
}
