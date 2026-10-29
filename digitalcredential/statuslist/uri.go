// The uri of a Status List Token, as its sub claim and as the uri of a
// Referenced Token (draft-ietf-oauth-status-list-21 §5.1, §6.2): RFC 7519 §2
// (a StringOrURI holding ":" MUST be a URI) and RFC 3986 §3, rule URI of
// Appendix A.

package statuslist

import (
	"errors"
	"net/netip"
	"strings"
)

// checkListURI is the rule for the uri of a Status List Token, which the
// token's sub and the Referenced Token's uri both meet (draft 21 §5.1: the
// two are equal): a URI conforming to RFC 3986 (§6.2; RFC 7519 §2: a
// StringOrURI holding ":" MUST be one), and with an http or https scheme a
// host: RFC 9110 §4.2.1 and §4.2.2 forbid a sender to generate one with an
// empty host and require a recipient to reject it as invalid. Any other
// scheme is accepted.
func checkListURI(s string) error {
	if !isURI(s) {
		return errors.New("is not a URI (RFC 3986)")
	}
	// RFC 3986 §3.1: a scheme compares case-insensitively.
	scheme, rest, _ := strings.Cut(s, ":")
	if (strings.EqualFold(scheme, "http") || strings.EqualFold(scheme, "https")) && !hasHost(rest) {
		return errors.New("is an http or https URI without a host (RFC 9110 §4.2.1, §4.2.2)")
	}
	return nil
}

// hasHost reports whether the part of a URI after "scheme:" starts with an
// authority whose host is not empty; isURI has checked its syntax.
func hasHost(rest string) bool {
	rest, ok := strings.CutPrefix(rest, "//")
	if !ok {
		return false
	}
	authority := rest
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		authority = rest[:i]
	}
	if _, hostport, ok := strings.Cut(authority, "@"); ok {
		authority = hostport
	}
	host, _, _ := strings.Cut(authority, ":")
	// An IP-literal starts with "[", which isURI checked is not empty.
	return host != "" || strings.HasPrefix(authority, "[")
}

// isURI reports whether s is a URI by RFC 3986 §3, checked per component on
// the raw string: url.Parse accepts characters RFC 3986 does not, and
// url.URL.String writes RawQuery back verbatim.
func isURI(s string) bool {
	s, fragment, ok := strings.Cut(s, "#")
	if ok && !uriChars(fragment, ":@/?") { // §3.5
		return false
	}
	s, query, ok := strings.Cut(s, "?")
	if ok && !uriChars(query, ":@/?") { // §3.4
		return false
	}
	scheme, path, ok := strings.Cut(s, ":")
	if !ok || !isScheme(scheme) {
		return false
	}
	if rest, ok := strings.CutPrefix(path, "//"); ok {
		authority, abempty, _ := strings.Cut(rest, "/")
		if !isAuthority(authority) {
			return false
		}
		path = abempty
	}
	// §3.3: every path form is segments of pchar joined by "/"; one that
	// starts with "//" was read as an authority above.
	return uriChars(path, ":@/")
}

// isScheme: RFC 3986 §3.1, ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ).
func isScheme(s string) bool {
	if s == "" || !isAlpha(s[0]) {
		return false
	}
	for i := 1; i < len(s); i++ {
		if c := s[i]; !isAlpha(c) && !isDigit(c) && c != '+' && c != '-' && c != '.' {
			return false
		}
	}
	return true
}

// isAuthority: RFC 3986 §3.2, [ userinfo "@" ] host [ ":" port ], where
// brackets appear only around an IP-literal host (§3.2.2) and port is
// *DIGIT (§3.2.3).
func isAuthority(s string) bool {
	if userinfo, hostport, ok := strings.Cut(s, "@"); ok {
		if !uriChars(userinfo, ":") { // §3.2.1
			return false
		}
		s = hostport
	}
	host, port := s, ""
	if bracketed, ok := strings.CutPrefix(s, "["); ok {
		literal, after, ok := strings.Cut(bracketed, "]")
		if !ok || !isIPLiteral(literal) {
			return false
		}
		host = ""
		if after != "" {
			p, ok := strings.CutPrefix(after, ":")
			if !ok {
				return false
			}
			port = p
		}
	} else {
		host, port, _ = strings.Cut(s, ":")
	}
	for i := 0; i < len(port); i++ {
		if !isDigit(port[i]) {
			return false
		}
	}
	// reg-name; IPv4address is made of the same characters.
	return uriChars(host, "")
}

// isIPLiteral: the inside of RFC 3986 §3.2.2 IP-literal, IPv6address or
// IPvFuture (its "v" is case-insensitive, §3.2.2). netip parses
// IPv6address but also accepts a zone, which the rule has no room for.
func isIPLiteral(s string) bool {
	if s != "" && (s[0] == 'v' || s[0] == 'V') {
		rest := s[1:]
		hex, tail, ok := strings.Cut(rest, ".")
		if !ok || hex == "" || tail == "" || strings.Contains(tail, "%") || !uriChars(tail, ":") {
			return false
		}
		for i := 0; i < len(hex); i++ {
			if !isHex(hex[i]) {
				return false
			}
		}
		return true
	}
	a, err := netip.ParseAddr(s)
	return err == nil && a.Is6() && a.Zone() == ""
}

// uriChars reports whether s holds only unreserved and sub-delims characters,
// valid pct-encoded triplets (RFC 3986 §2.1-2.3) and bytes listed in extra.
func uriChars(s, extra string) bool {
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '%':
			if i+2 >= len(s) || !isHex(s[i+1]) || !isHex(s[i+2]) {
				return false
			}
			i += 2
		case isAlpha(c), isDigit(c), strings.IndexByte("-._~!$&'()*+,;=", c) >= 0, strings.IndexByte(extra, c) >= 0:
		default:
			return false
		}
	}
	return true
}

func isAlpha(c byte) bool { return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' }
func isDigit(c byte) bool { return '0' <= c && c <= '9' }
func isHex(c byte) bool   { return isDigit(c) || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F' }
