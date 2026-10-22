package jose

import (
	"encoding/base64"
	"fmt"
	"strings"
)

var strictRawURL = base64.RawURLEncoding.Strict()

// EncodeSegment encodes b as base64url without padding, the form every JWS
// segment and every SD-JWT disclosure uses.
func EncodeSegment(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// DecodeSegment decodes base64url without padding and refuses every
// alternative spelling of the same bytes, so that one token has one encoding
// and digests over received strings cannot be dodged:
//   - Strict() rejects non-zero trailing bits ("…Q" and "…R" would otherwise
//     decode to the same bytes);
//   - '\r' and '\n' are rejected here, because Go's decoder skips them silently
//     even in strict mode.
func DecodeSegment(s string) ([]byte, error) {
	if strings.ContainsAny(s, "\r\n") {
		return nil, fmt.Errorf("%w: base64url contains a line break", ErrMalformed)
	}
	b, err := strictRawURL.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: base64url: %v", ErrMalformed, err)
	}
	return b, nil
}
