// Package allowlist matches a URL taken from a token against the origins a
// Relying Party trusts: the trusted issuers of issuermeta
// (draft-ietf-oauth-sd-jwt-vc-19 §2.5) and the trusted Type Metadata
// publishers of typemeta (§7.8). The list is the Relying Party's policy;
// how an entry covers a URL, and which redirects a retrieval follows
// (Redirects), is this package's rule, shared so both read it alike.
//
// An entry is an origin written "https://host" or "https://host:port", with
// or without a final "/", which covers every URL of that origin; or
// "https://*.host", which covers every URL of an origin whose host is a
// subdomain of host. An empty list covers every URL, so there is no entry
// for that. An origin compares the host in any ASCII case and the port with
// the scheme's default implied (RFC 6454 §4), on the parsed URL, so a path
// cannot pose as a host. Entries name origins only, as in CORS: the origin's server
// decides which resource a path names (RFC 3986 §3.2), and the origin is
// where trust can stop (RFC 6454 §3.2). A rule finer than an origin, such as
// one iss of a shared host, belongs to the caller's own Resolver around the
// one this package serves.
package allowlist

import (
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/pilacorp/go-credential-sdk/digitalcredential/internal/safehttp"
)

// List is the entries a caller configured. An empty List covers every URL.
type List struct {
	any     bool
	origins []origin
}

// origin is an entry: host in lower case, without the "*." of a subdomain
// entry.
type origin struct {
	host, port string
	subdomain  bool
}

// Hints are the parts of Check's texts that depend on the caller's
// configuration.
type Hints struct {
	// All says how to cover every https origin, for the entry "*".
	All string
	// Finer, when set, says how to trust some URLs of an origin, for an
	// entry with a path.
	Finer string
}

// Check says why e cannot be an entry, for an error that names the
// caller's configuration field, or returns "" when it can.
func Check(e string, h Hints) string {
	switch {
	case e == "*":
		return `is "*", which is not an entry; to cover every https origin, ` + h.All
	case len(e) < len("https://") || !strings.EqualFold(e[:len("https://")], "https://"):
		return `does not start with https://; list origins as "https://host" or "https://*.host"`
	}
	o, ok := parseOrigin(e)
	switch {
	case !ok && h.Finer != "":
		return notOrigin + "; to trust some URLs of an origin, " + h.Finer
	case !ok:
		return notOrigin
	case !plainHost(o.host):
		// A URL with the same host written another way, with a final "." or
		// as Unicode rather than its A-label, would not match the entry.
		return `has a host that is not ASCII or has an empty label, a final "." included; write the host in ASCII, each non-ASCII label as its A-label ("xn--..."), with no empty label`
	case (strings.Contains(o.host, ":") || strings.Contains(e, "[")) && (o.subdomain || !ipv6(o.host)):
		// url.Parse of an older Go, or of a module whose go line is older
		// than 1.26, reads a second ":" into the host and takes brackets
		// around a name (RFC 3986 §3.2.2 brackets only an IP literal); "*."
		// before an IPv6 address would match no URL.
		return `has ":" or "[" in a host that is not an IPv6 address, or "*." before an IPv6 address; write the port once, after the host, and an IPv6 address alone, as "https://[address]"`
	case !plainPort(o.port):
		// Port compares the port as written, so "0443" would not match 443.
		return "has a port that is not a number from 1 to 65535 without leading zeros"
	}
	return ""
}

const notOrigin = `is not an origin "https://host" or "https://*.host", with an optional port and final "/": an entry names a whole origin, so it has no path, query, userinfo or other "*"`

// plainHost reports whether host is ASCII and has no empty label.
func plainHost(host string) bool {
	for i := 0; i < len(host); i++ {
		if host[i] >= 0x80 {
			return false
		}
	}
	return !strings.HasPrefix(host, ".") && !strings.HasSuffix(host, ".") && !strings.Contains(host, "..")
}

// ipv6 reports whether host is an IPv6 address.
func ipv6(host string) bool {
	a, err := netip.ParseAddr(host)
	return err == nil && a.Is6()
}

// plainPort reports whether port, digits as url.Parse leaves it, is 1 to
// 65535 without leading zeros.
func plainPort(port string) bool {
	n, err := strconv.Atoi(port)
	return err == nil && n >= 1 && n <= 65535 && port == strconv.Itoa(n)
}

// parseOrigin reads e, which starts with https://, as an origin entry: a
// host, an optional port and an optional "/", nothing else, the host
// optionally after "*.".
func parseOrigin(e string) (origin, bool) {
	sub := strings.HasPrefix(e[len("https://"):], "*.")
	if sub {
		e = "https://" + e[len("https://*."):]
	}
	u, err := url.Parse(e)
	if err != nil || !safehttp.HTTPSURL(u) || (u.Path != "" && u.Path != "/") || strings.ContainsAny(e, "?#*") {
		return origin{}, false
	}
	return origin{host: asciiLower(u.Hostname()), port: safehttp.Port(u), subdomain: sub}, true
}

// New returns a List of entries, each of which Check accepted.
func New(entries []string) List {
	return List{any: len(entries) == 0, origins: parseAll(entries)}
}

func parseAll(entries []string) []origin {
	var origins []origin
	for _, e := range entries {
		if o, ok := parseOrigin(e); ok {
			origins = append(origins, o)
		}
	}
	return origins
}

// Covers reports whether l covers u, an https URL.
func (l List) Covers(u *url.URL) bool {
	return l.any || slices.ContainsFunc(l.origins, func(o origin) bool { return o.covers(u) })
}

func (o origin) covers(u *url.URL) bool {
	host := asciiLower(u.Hostname())
	if o.subdomain {
		// An IPv6 literal is no subdomain, though its zone may end in
		// "."+o.host: "[2001:db8::1%25.host]" dials 2001:db8::1.
		if strings.Contains(host, ":") || !strings.HasSuffix(host, "."+o.host) {
			return false
		}
	} else if host != o.host {
		return false
	}
	return safehttp.Port(u) == o.port
}

// Redirects is where a retrieval follows a redirect. Every one follows a
// redirect within the origin of the URL it requested; RedirectsTo adds the
// origins of a list, and RedirectsAny every https URL. The zero value is
// the first.
type Redirects struct {
	any bool
	to  List
}

// RedirectsTo also follows a redirect to an origin entries cover, each of
// which Check accepted. Unlike New, no entries adds nothing.
func RedirectsTo(entries []string) Redirects {
	return Redirects{to: List{origins: parseAll(entries)}}
}

// RedirectsAny follows a redirect to any URL safehttp lets through.
func RedirectsAny() Redirects { return Redirects{any: true} }

// Follows reports whether a retrieval that requested start follows a
// redirect to target, both https URLs; it is a safehttp.Limits.Follow.
func (r Redirects) Follows(start, target *url.URL) bool {
	return r.any || sameOrigin(start, target) || r.to.Covers(target)
}

// sameOrigin reports whether a and b, both https, have one origin: the host
// in any ASCII case, and the port, the scheme's default when absent.
func sameOrigin(a, b *url.URL) bool {
	return asciiLower(a.Hostname()) == asciiLower(b.Hostname()) && safehttp.Port(a) == safehttp.Port(b)
}

// asciiLower maps A to Z of s to lower case and leaves every other byte, as
// RFC 6454 §4 lowers a host (i;ascii-casemap): Unicode hosts that fold to
// one another are different hosts to the transport, which looks up their
// A-labels.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}
