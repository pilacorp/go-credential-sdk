// Package jose holds what the JOSE packages of this module share: strict
// base64url (RFC 4648 §5 alphabet; RFC 7515 §2, no padding, line breaks or
// other characters; RFC 4648 §3.3 and §3.5), strict JSON (RFC 8259, RFC 7515
// §10.12) and the error sentinels. Compact JWS with ES256 and ES256K (RFC
// 7515, RFC 7518 §3.4, RFC 8812 §3.2) is in jose/jws; EC public keys as JWK
// (RFC 7517, RFC 7518 §6.2, RFC 8812 §3.1) are in jose/jwk.
package jose

import (
	"encoding/base64"
	"fmt"
	"strings"
)

var strictRawURL = base64.RawURLEncoding.Strict()

// EncodeSegment encodes b as base64url without padding, the form every JWS
// segment and every SD-JWT disclosure uses (RFC 7515 §2).
func EncodeSegment(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// DecodeSegment decodes base64url without padding and refuses every
// alternative spelling of the same bytes, so there is one spelling per segment
// and digests over received strings cannot be dodged.
func DecodeSegment(s string) ([]byte, error) {
	// RFC 4648 §3.3 and RFC 7515 §2: no line breaks. Checked by hand because
	// encoding/base64 skips \r and \n, even in strict mode.
	if strings.ContainsAny(s, "\r\n") {
		return nil, fmt.Errorf("%w: base64url contains a line break", ErrMalformed)
	}
	// RFC 4648 §3.5: a decoder MAY reject non-zero pad bits; Strict() does,
	// so "QQ" and "QR" do not both decode to "A". RFC 4648 §3.3: characters
	// outside the alphabet, '=' included (RFC 7515 §2), are rejected.
	b, err := strictRawURL.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: base64url: %v", ErrMalformed, err)
	}
	return b, nil
}
