// The Resolver's cache of issuer keys; how long a response may be reused is
// internal/httpcache (RFC 9111 §4.2, §5.2).

package issuermeta

import (
	"slices"
	"strings"
	"time"

	"github.com/pilacorp/go-credential-sdk/digitalcredential/issuerkey"
)

// Estimated heap bytes, measured on go1.24.3 and go1.26.0 (arm64) with 4,000
// entries: a cached key is its issuerkey.PublicKey, its *ecdsa.PublicKey and two
// big.Int of 32 bytes, plus the kid; an entry is its share of the map, its
// slice header, two times and iss.
const (
	keyCost   = 250
	entryCost = 222
)

type cacheEntry struct {
	keys    []issuerkey.PublicKey // never handed out: cached returns a copy
	sent    time.Time             // when the metadata request of this answer was sent
	expires time.Time
	size    int
}

// cached returns a copy of the keys cached for iss, and false when there are
// none or they have expired.
func (r *Resolver) cached(iss string) ([]issuerkey.PublicKey, bool) {
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
// issuer's clock sets). With Config.DisableCache, or an expiry not after now,
// nothing is stored. When the cache is full, expired entries are dropped; if
// there is still no room, keys are not cached, which costs a retrieval,
// never a wrong key.
func (r *Resolver) store(iss string, keys []issuerkey.PublicKey, sent, expires time.Time) {
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
