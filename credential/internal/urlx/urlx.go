// Package urlx parses URLs that come from a credential as the WHATWG URL
// Standard does, at a cost linear in their length.
package urlx

import (
	"fmt"
	"strings"

	whatwgurl "github.com/nlnwa/whatwg-url/url"

	"github.com/pilacorp/go-credential-sdk/credential/internal/errtext"
)

// MaxBytes bounds a URL. The URL Standard sets no limit, and the parser takes
// time quadratic in the length of a userinfo or host.
const MaxBytes = 8 << 10

// maxAuthorityBytes bounds the authority (userinfo, host and port). A DNS name
// is at most 253 bytes. The parser spends far more per authority byte than
// per path byte (an 8 KiB authority of '@' costs 140 ms), so this bound, not
// MaxBytes, keeps a document of many URLs cheap. It refuses a few valid URLs:
// a host percent-encoded or IDN-encoded past 255 bytes, a port padded with
// zeros.
const maxAuthorityBytes = 255

// Parse parses raw as a URL of the WHATWG URL Standard, with no base, so a
// URL with no scheme fails. It refuses, before parsing, a URL longer than
// MaxBytes and one whose authority is longer than maxAuthorityBytes. field
// names the property in error text; raw and the parser's message, which
// holds the whole input, are clipped there.
func Parse(raw, field string) (*whatwgurl.Url, error) {
	if len(raw) > MaxBytes {
		return nil, fmt.Errorf("%s is %d bytes; this SDK accepts at most %d for a URL", field, len(raw), MaxBytes)
	}
	if err := checkAuthority(raw); err != nil {
		return nil, fmt.Errorf("%s %q %w", field, errtext.Clip(raw), err)
	}
	u, err := whatwgurl.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%s %q must be a URL of the WHATWG URL Standard: %s", field, errtext.Clip(raw), errtext.Clip(err.Error()))
	}
	return u, nil
}

// checkAuthority finds the authority the way the WHATWG parser does: leading
// and trailing C0 controls and spaces trimmed, tab and newline removed; for a
// special scheme other than file every '/' and '\' after "scheme:" skipped,
// and the authority ends at '/', '\', '?' or '#'; for file only after exactly
// two of '/' or '\'; for another scheme only after "//", ending at '/', '?' or
// '#'. A URL with an opaque path has no authority.
func checkAuthority(raw string) error {
	s := strings.TrimFunc(raw, func(r rune) bool { return r <= ' ' })
	s = strings.NewReplacer("\t", "", "\n", "", "\r", "").Replace(s)
	colon := strings.IndexByte(s, ':')
	if colon < 0 {
		return nil // no scheme: the parse fails at once
	}
	rest := s[colon+1:]
	enders := "/?#"
	switch strings.ToLower(s[:colon]) {
	case "ftp", "http", "https", "ws", "wss":
		rest = strings.TrimLeft(rest, `/\`)
		enders = `/\?#`
	case "file":
		if len(rest) < 2 || !isSlash(rest[0]) || !isSlash(rest[1]) {
			return nil
		}
		rest = rest[2:]
		enders = `/\?#`
	default:
		var ok bool
		if rest, ok = strings.CutPrefix(rest, "//"); !ok {
			return nil
		}
	}
	authority := rest
	if end := strings.IndexAny(rest, enders); end >= 0 {
		authority = rest[:end]
	}
	if len(authority) > maxAuthorityBytes {
		return fmt.Errorf("has a %d-byte authority (userinfo, host and port); this SDK accepts at most %d", len(authority), maxAuthorityBytes)
	}
	return nil
}

func isSlash(c byte) bool { return c == '/' || c == '\\' }
