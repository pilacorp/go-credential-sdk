// Ported from sd-jwt-python (Apache-2.0), src/sd_jwt/disclosure.py
// (SDJWTDisclosure), and eudi-lib-jvm-sdjwt-kt (Apache-2.0),
// src/main/kotlin/eu/europa/ec/eudi/sdjwt/Disclosure.kt. See jose/NOTICE.

package sdjwt

import (
	"crypto/sha256"
	"fmt"

	"github.com/pilacorp/go-credential-sdk/jose"
)

// Names RFC 9901 reserves for its own structure (§4.1.1, §4.2.4).
const (
	keySD       = "_sd"
	keySDAlg    = "_sd_alg"
	keyEllipsis = "..."
	sdAlgSHA256 = "sha-256"
)

// Disclosure is one concealed claim: an object property [salt, name, value]
// (RFC 9901 §4.2.1) or an array element [salt, value] (§4.2.2).
type Disclosure struct {
	Salt string
	// Name is the claim name of an object property and empty for an array
	// element. "" is also a valid claim name, so ArrayElement tells the two
	// kinds apart.
	Name  string
	Value any
	// ArrayElement is true for [salt, value], false for [salt, name, value].
	ArrayElement bool
	// Encoded is the base64url string, exactly as received or created.
	Encoded string
	// Digest is base64url(SHA-256(US-ASCII of Encoded)), RFC 9901 §4.2.3.
	Digest string
}

// ParseDisclosure reads a received disclosure. Every error wraps
// jose.ErrMalformed:
//   - base64url that is not strict, or JSON with duplicate keys, trailing data
//     or invalid UTF-8 (jose.DecodeSegment, jose.DecodeJSON);
//   - anything but a JSON array of 2 or 3 items, or a salt or claim name that
//     is not a string (§4.2.1, §4.2.2);
//   - the claim name _sd or ... (§4.2.1, §7.1 step 3c.ii.2), or _sd_alg:
//     §4.1.1 lets it appear only at the top level of the Issuer-signed
//     payload, and the algorithm is needed before any disclosure is hashed
//     (§7.1 step 3a). Stricter than §7.1, which rejects it for its name only
//     where the level of the _sd key referencing it already holds _sd_alg
//     (step 3c.ii.3), and otherwise inserts it there (step 3c.ii.4); step 3f
//     removes "the claim _sd_alg", read as the top-level one of §4.1.1, so a
//     nested one stays.
//
// Digest is computed over encoded itself, never over re-encoded JSON
// (§4.2.3), since one value may be written several ways (§4.2.1).
func ParseDisclosure(encoded string) (Disclosure, error) {
	raw, err := jose.DecodeSegment(encoded)
	if err != nil {
		return Disclosure{}, fmt.Errorf("sdjwt: disclosure: %w", err)
	}
	v, err := jose.DecodeJSON(raw)
	if err != nil {
		return Disclosure{}, fmt.Errorf("sdjwt: disclosure: %w", err)
	}
	items, ok := v.([]any)
	if !ok || (len(items) != 2 && len(items) != 3) {
		return Disclosure{}, fmt.Errorf("%w: sdjwt: a disclosure is a JSON array of 2 or 3 items", jose.ErrMalformed)
	}
	salt, ok := items[0].(string)
	if !ok {
		return Disclosure{}, fmt.Errorf("%w: sdjwt: disclosure salt is not a string", jose.ErrMalformed)
	}
	d := Disclosure{Salt: salt, Encoded: encoded, Digest: digestOf(encoded)}
	if len(items) == 2 {
		d.ArrayElement, d.Value = true, items[1]
		return d, nil
	}
	name, ok := items[1].(string)
	if !ok {
		return Disclosure{}, fmt.Errorf("%w: sdjwt: disclosure claim name is not a string", jose.ErrMalformed)
	}
	if reserved(name) {
		return Disclosure{}, fmt.Errorf("%w: sdjwt: disclosure claim name %q is reserved", jose.ErrMalformed, name)
	}
	d.Name, d.Value = name, items[2]
	return d, nil
}

func reserved(name string) bool {
	return name == keySD || name == keySDAlg || name == keyEllipsis
}

// digestOf is base64url(SHA-256(US-ASCII of s)), RFC 9901 §4.2.3: the digest
// of a disclosure from its encoded string.
func digestOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return jose.EncodeSegment(sum[:])
}
