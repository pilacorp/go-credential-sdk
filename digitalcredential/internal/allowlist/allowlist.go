// Package allowlist matches a URL taken from a token against the https URLs
// a Relying Party trusts: the allowed issuers of issuermeta
// (draft-ietf-oauth-sd-jwt-vc-19 §2.5) and the allowed Type Metadata
// publishers of typemeta (§7.8). The list is the Relying Party's policy;
// how an entry covers a URL is this package's rule, shared so both read it
// alike.
package allowlist

import (
	"net/url"
	"slices"
	"strings"
)

// List is a copy of the entries a caller configured. An entry ending in "/"
// covers every URL that starts with it, except one whose path has a "." or
// ".." segment; any other entry covers only the URL equal to it. Matching is
// byte for byte, so case-sensitive.
type List struct{ entries []string }

// ValidEntry reports whether e starts with https://, the scheme in any case.
// Any other entry would match no URL or, like "https:/", every one.
func ValidEntry(e string) bool {
	return len(e) >= len("https://") && strings.EqualFold(e[:len("https://")], "https://")
}

// New returns a List of a copy of entries. The caller checks each entry with
// ValidEntry first, so its error can name its own configuration field.
func New(entries []string) List { return List{entries: slices.Clone(entries)} }

// Covers reports whether an entry covers raw, u being raw parsed, and whether
// an entry ending in "/" starts raw but the dot rule refused it. raw comes
// from a token not yet verified, so its path is scanned at most once, and
// only when such an entry starts it.
func (l List) Covers(raw string, u *url.URL) (ok, dot bool) {
	for _, e := range l.entries {
		switch {
		case !strings.HasSuffix(e, "/"):
			if raw == e {
				return true, false
			}
		case dot || !strings.HasPrefix(raw, e):
		case hasDotSegment(u.Path):
			dot = true
		default:
			return true, false
		}
	}
	return false, dot
}

// hasDotSegment reports whether path, already decoded once by url.Parse, has a
// "." or ".." segment. Raw and %2e forms name a resource outside an entry
// ending in "/" (RFC 3986 §2.3, §6.2.2.3); "\" and %2F as separators and ";"
// path parameters are SDK policy: some servers resolve them so, and no issuer
// identifier needs them. Under draft-ietf-oauth-sd-jwt-vc-20 §4 an issuer
// MUST NOT use dot segments at all, and the check would move to issuermeta.
func hasDotSegment(path string) bool {
	for s := range strings.FieldsFuncSeq(path, func(c rune) bool { return c == '/' || c == '\\' }) {
		if s, _, _ = strings.Cut(s, ";"); s == "." || s == ".." {
			return true
		}
	}
	return false
}
