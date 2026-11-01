// Package httpcache computes how long a fetched document may be reused, as
// RFC 9111 §4.2 and §5.2 allow a private cache, for the caches of issuermeta
// and typemeta. It stores nothing itself.
package httpcache

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/pilacorp/go-credential-sdk/digitalcredential/internal/safehttp"
)

// Get retrieves rawURL through safehttp.Get and returns the body and how
// long, from the time the request was sent, it may be reused: the least
// Freshness of the final response and of every redirect leading to it, since
// reusing the answer to rawURL reuses those redirects too (RFC 9111 §4), at
// most ceiling. The redirect hook wraps the CheckRedirect of c, which runs
// unchanged.
func Get(ctx context.Context, c *http.Client, rawURL string, mediaTypes []string, l safehttp.Limits, ceiling time.Duration) ([]byte, time.Duration, error) {
	cc := *c
	next := cc.CheckRedirect
	fresh := ceiling
	cc.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		fresh = min(fresh, Freshness(req.Response.Header, ceiling))
		if next != nil {
			return next(req, via)
		}
		return nil
	}
	body, h, err := safehttp.Get(ctx, &cc, rawURL, mediaTypes, l)
	if err != nil {
		return nil, 0, err
	}
	return body, min(fresh, Freshness(h, ceiling)), nil
}

// Freshness returns how long, from the time the request was sent, a response
// with header h may be reused: max-age minus Age (RFC 9111 §4.2.1, §4.2.3),
// at most ceiling. It is 0, not stored, whenever RFC 9111 lets a cache not
// store (§2) and the header gives a reason to: no-cache or no-store
// (§5.2.2.4, §5.2.2.5), a Vary with a member other than Accept or
// Accept-Encoding, `*` included (§4.1), no max-age, or a max-age that is
// invalid or appears more than once (§4.2.1).
func Freshness(h http.Header, ceiling time.Duration) time.Duration {
	cc := strings.Join(h.Values("Cache-Control"), ",")
	// A quoted-string argument (§5.2) can hold a comma, so splitting at commas
	// would read `x=", max-age=86400"` as a max-age the server never sent.
	// No directive this package reads needs quotes; such a response is not
	// stored.
	if strings.Contains(cc, `"`) {
		return 0
	}
	// RFC 9111 §4.1: a response is reused only while every request header its
	// Vary names matches. The callers set Accept and Accept-Encoding, the same
	// for every retrieval of a document (safehttp.Get sets them; net/http
	// copies them to every redirect); any other header can differ unseen (a
	// cookie jar or Transport of the client, net/http's User-Agent per
	// protocol), and "*" never matches.
	for _, v := range h.Values("Vary") {
		for m := range strings.SplitSeq(v, ",") {
			m = strings.TrimSpace(m)
			if m != "" && !strings.EqualFold(m, "Accept") && !strings.EqualFold(m, "Accept-Encoding") {
				return 0
			}
		}
	}
	maxAge, seen := int64(0), false
	for d := range strings.SplitSeq(cc, ",") {
		// An empty list element (RFC 9110 §5.6.1.2) matches no case.
		name, arg, _ := strings.Cut(strings.TrimSpace(d), "=")
		switch {
		case strings.EqualFold(name, "no-store"), strings.EqualFold(name, "no-cache"):
			return 0
		case strings.EqualFold(name, "max-age"):
			n, ok := deltaSeconds(arg)
			if seen || !ok {
				return 0
			}
			maxAge, seen = n, true
		}
	}
	// Without a max-age, maxAge stays 0 and the response is not stored.
	// RFC 9111 §5.1: of an Age list, the first member is used; an invalid
	// Age is ignored.
	first, _, _ := strings.Cut(h.Get("Age"), ",")
	if age, ok := deltaSeconds(strings.TrimSpace(first)); ok {
		maxAge -= age
	}
	if maxAge <= 0 {
		return 0
	}
	return min(time.Duration(maxAge)*time.Second, ceiling)
}

// deltaSeconds parses delta-seconds, 1*DIGIT, capped at 2^31 as RFC 9111
// §1.2.2 asks of a value too large to hold. strconv.ParseInt alone would
// accept a sign. "" is invalid, so a bare max-age and max-age= are not
// stored.
func deltaSeconds(s string) (int64, bool) {
	if s == "" || strings.Trim(s, "0123456789") != "" {
		return 0, false
	}
	const limit = 1 << 31
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n > limit {
		return limit, true // only digits, so err is a range error
	}
	return n, true
}
