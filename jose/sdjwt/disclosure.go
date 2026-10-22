// Ported from sd-jwt-python (Apache-2.0), src/sd_jwt/disclosure.py
// (SDJWTDisclosure), and eudi-lib-jvm-sdjwt-kt (Apache-2.0),
// src/main/kotlin/eu/europa/ec/eudi/sdjwt/Disclosure.kt (ObjectProperty,
// ArrayElement, decode) and Util.kt (ensureValidAttributeName). See jose/NOTICE.

package sdjwt

import (
	"crypto/sha256"
	"fmt"

	"github.com/pilacorp/go-credential-sdk/jose"
)

// Reserved names (RFC 9901 sections 4.1.1, 4.2.4).
const (
	keySD       = "_sd"
	keySDAlg    = "_sd_alg"
	keyEllipsis = "..."
	sdAlgSHA256 = "sha-256"
)

// Disclosure is one concealed claim: an object property [salt, name, value]
// or an array element [salt, value].
type Disclosure struct {
	Salt string
	// Name is the claim name of an object property; empty for an array
	// element. "" is also a valid claim name, so use ArrayElement to tell the
	// two kinds apart.
	Name  string
	Value any
	// ArrayElement is true for [salt, value], false for [salt, name, value].
	ArrayElement bool
	// Encoded is the base64url string, exactly as received or as created.
	Encoded string
	// Digest is base64url(SHA-256(ASCII of Encoded)).
	Digest string
}

// ParseDisclosure reads a received disclosure. It rejects:
//   - base64url that is not strict (jose.DecodeSegment);
//   - JSON with duplicate keys at any depth, trailing data or invalid UTF-8
//     (jose.DecodeJSON);
//   - anything but a JSON array of 2 or 3 items, a salt that is not a string,
//     a name that is not a string (ErrDisclosureShape);
//   - the name _sd, ... or _sd_alg (ErrReservedName).
//
// Digest is computed over encoded itself, never over re-encoded JSON.
func ParseDisclosure(encoded string) (Disclosure, error) {
	raw, err := jose.DecodeSegment(encoded)
	if err != nil {
		return Disclosure{}, fmt.Errorf("%w: disclosure: %w", ErrMalformed, err)
	}
	v, err := jose.DecodeJSON(raw)
	if err != nil {
		return Disclosure{}, fmt.Errorf("%w: disclosure: %w", ErrMalformed, err)
	}
	items, ok := v.([]any)
	if !ok || (len(items) != 2 && len(items) != 3) {
		return Disclosure{}, fmt.Errorf("%w: a disclosure is a JSON array of 2 or 3 items", ErrDisclosureShape)
	}
	salt, ok := items[0].(string)
	if !ok {
		return Disclosure{}, fmt.Errorf("%w: salt is not a string", ErrDisclosureShape)
	}
	d := Disclosure{Salt: salt, Encoded: encoded, Digest: digestOf(encoded)}
	if len(items) == 2 {
		d.ArrayElement = true
		d.Value = items[1]
		return d, nil
	}
	name, ok := items[1].(string)
	if !ok {
		return Disclosure{}, fmt.Errorf("%w: claim name is not a string", ErrDisclosureShape)
	}
	if err := checkClaimName(name); err != nil {
		return Disclosure{}, err
	}
	d.Name, d.Value = name, items[2]
	return d, nil
}

// checkClaimName refuses the names RFC 9901 reserves for its own structure;
// _sd_alg is refused too, as in the Kotlin library, since it may only appear
// at the top level of the issuer's payload.
func checkClaimName(name string) error {
	switch name {
	case keySD, keySDAlg, keyEllipsis:
		return fmt.Errorf("%w: claim name %q", ErrReservedName, name)
	}
	return nil
}

// digestOf is base64url(SHA-256(ASCII of s)): the digest of a disclosure, a
// decoy, and the sd_hash of a presentation.
func digestOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return jose.EncodeSegment(sum[:])
}
