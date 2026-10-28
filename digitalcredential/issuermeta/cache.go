// The Resolver's cache of issuer keys, and how long a response may be reused
// (RFC 9111 §4.2, §5.2).

package issuermeta

import (
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/pilacorp/go-credential-sdk/digitalcredential/issuerkey"
)

// Estimated heap bytes, measured on go1.24.3 and go1.26.0 (arm64) with 4,000
// entries: a cached key is its issuerkey.Key, its *ecdsa.PublicKey and two
// big.Int of 32 bytes, plus the kid; an entry is its share of the map, its
// slice header, two times and iss.
const (
	keyCost   = 250
	entryCost = 222
)

type cacheEntry struct {
	keys    []issuerkey.Key // never handed out: cached returns a copy
	sent    time.Time       // when the metadata request of this answer was sent
	expires time.Time
	size    int
}

// cached returns a copy of the keys cached for iss, and false when there are
// none or they have expired.
func (r *Resolver) cached(iss string) ([]issuerkey.Key, bool) {
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	if e, ok := r.cache[iss]; ok && now.Before(e.expires) {
		return slices.Clone(e.keys), true
	}
	return nil, false
}

// store caches keys for iss until expires, keys answering a request sent at
// sent. It replaces the entry of iss unless that entry is live and answers a
// request sent later, so of two concurrent misses the newer answer stays
// (SDK policy; RFC 9111 §4 orders stored responses by Date, which the
// issuer's clock sets). With WithoutCache, or an expiry not after now,
// nothing is stored. When the cache is full, expired entries are dropped; if
// there is still no room, keys are not cached, which costs a retrieval,
// never a wrong key.
func (r *Resolver) store(iss string, keys []issuerkey.Key, sent, expires time.Time) {
	now := r.now()
	if r.noCache || !now.Before(expires) {
		return
	}
	size := entryCost + len(iss)
	for _, k := range keys {
		size += keyCost + len(k.KID)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if old, ok := r.cache[iss]; ok {
		if now.Before(old.expires) && old.sent.After(sent) {
			return
		}
		r.used -= old.size
		delete(r.cache, iss)
	}
	// Scanned only once an entry may have expired: while all are live, a scan
	// frees nothing and holds mu over the whole map on every refused store.
	if r.used+size > maxCacheBytes && !now.Before(r.purgeAt) {
		r.purgeAt = time.Time{}
		for k, e := range r.cache {
			if !now.Before(e.expires) {
				r.used -= e.size
				delete(r.cache, k)
			} else if r.purgeAt.IsZero() || e.expires.Before(r.purgeAt) {
				r.purgeAt = e.expires
			}
		}
	}
	if r.used+size > maxCacheBytes {
		return
	}
	// iss is cloned because Keys may get a substring of a larger buffer, the
	// token, and the budget counts only what the entry holds.
	r.cache[strings.Clone(iss)] = cacheEntry{keys: slices.Clone(keys), sent: sent, expires: expires, size: size}
	r.used += size
	if r.purgeAt.IsZero() || expires.Before(r.purgeAt) {
		r.purgeAt = expires
	}
}

// freshness returns how long, from the time the request was sent, a response
// with header h may be reused: max-age minus Age (RFC 9111 §4.2.1, §4.2.3),
// at most maxCacheLifetime. It is 0, not stored, whenever RFC 9111 lets a
// cache not store (§2) and the header gives a reason to: no-cache or no-store
// (§5.2.2.4, §5.2.2.5), a Vary with a member other than Accept or
// Accept-Encoding, `*` included (§4.1), no max-age, or a max-age that is
// invalid or appears more than once (§4.2.1).
func freshness(h http.Header) time.Duration {
	cc := strings.Join(h.Values("Cache-Control"), ",")
	// A quoted-string argument (§5.2) can hold a comma, so splitting at commas
	// would read `x=", max-age=86400"` as a max-age the server never sent.
	// No directive this Resolver reads needs quotes; such a response is not
	// stored.
	if strings.Contains(cc, `"`) {
		return 0
	}
	// RFC 9111 §4.1: a response is reused only while every request header its
	// Vary names matches. The Resolver sets Accept and Accept-Encoding, the same
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
	return min(time.Duration(maxAge)*time.Second, maxCacheLifetime)
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
