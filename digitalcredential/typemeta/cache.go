// The cache of NewHTTPResolver; how long a response without integrity may be
// reused is internal/httpcache (RFC 9111 §4.2, §5.2).

package typemeta

import (
	"slices"
	"strings"
	"time"
)

// entryCost estimates the heap of an entry beside the bytes it holds: its
// share of the map, the Ref's two string headers, the slice header and two
// times.
const entryCost = 200

type cacheEntry struct {
	doc     []byte    // never handed out: cached returns a copy
	sent    time.Time // when the request of this answer was sent
	expires time.Time // zero: no expiry, the document matched its integrity; evicted oldest first when the cache is full
	size    int
}

func (e cacheEntry) live(now time.Time) bool {
	return e.expires.IsZero() || now.Before(e.expires)
}

// cached returns a copy of the document cached for ref, and false when there
// is none or it has expired.
func (r *httpResolver) cached(ref Ref) ([]byte, bool) {
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	if e, ok := r.cache[ref]; ok && e.live(now) {
		return slices.Clone(e.doc), true
	}
	return nil, false
}

// store caches doc for ref until expires, zero for no expiry, doc answering
// a request sent at sent. As issuermeta's store does, it keeps the entry of
// ref when that one is live and answers a later request, and with
// Config.DisableCache, an expiry not after now or a full cache stores
// nothing, which costs a retrieval, never a wrong document. A full cache
// first drops its expired entries, then entries with no expiry, the oldest
// sent first, so that one integrity value written many ways, or many types,
// costs retrievals and never a cache that stores nothing until restart. When
// the live entries that expire leave no room, it stores nothing.
func (r *httpResolver) store(ref Ref, doc []byte, sent, expires time.Time) {
	now := r.now()
	if r.noCache || !expires.IsZero() && !now.Before(expires) {
		return
	}
	size := entryCost + len(ref.VCT) + len(ref.Integrity) + len(doc)
	r.mu.Lock()
	defer r.mu.Unlock()
	if old, ok := r.cache[ref]; ok {
		if old.live(now) && old.sent.After(sent) {
			return
		}
		r.used -= old.size
		if old.expires.IsZero() {
			r.pinnedBytes -= old.size
		}
		delete(r.cache, ref)
	}
	if r.used+size > maxCacheBytes && !r.purgeAt.IsZero() && !now.Before(r.purgeAt) {
		r.purgeAt = time.Time{}
		for k, e := range r.cache {
			switch {
			case !e.live(now):
				r.used -= e.size
				delete(r.cache, k)
			case e.expires.IsZero():
			case r.purgeAt.IsZero() || e.expires.Before(r.purgeAt):
				r.purgeAt = e.expires
			}
		}
	}
	if r.used+size > maxCacheBytes && !r.evictPinned(size) {
		return
	}
	// The Ref's strings are cloned because Load passes substrings of a
	// larger buffer, the token or a parent document.
	key := Ref{VCT: strings.Clone(ref.VCT), Integrity: strings.Clone(ref.Integrity)}
	r.cache[key] = cacheEntry{doc: slices.Clone(doc), sent: sent, expires: expires, size: size}
	r.used += size
	if expires.IsZero() {
		r.pinnedBytes += size
	}
	if !expires.IsZero() && (r.purgeAt.IsZero() || expires.Before(r.purgeAt)) {
		r.purgeAt = expires
	}
}

// evictPinned drops entries with no expiry, the oldest sent first, until an
// entry of size fits, and reports whether it does. It drops nothing, and
// scans nothing, when dropping all of them would not be enough. r.mu is held.
func (r *httpResolver) evictPinned(size int) bool {
	if maxCacheBytes-r.used+r.pinnedBytes < size {
		return false
	}
	type pin struct {
		ref  Ref
		sent time.Time
	}
	var pinned []pin
	for k, e := range r.cache {
		if e.expires.IsZero() {
			pinned = append(pinned, pin{k, e.sent})
		}
	}
	slices.SortFunc(pinned, func(a, b pin) int { return a.sent.Compare(b.sent) })
	for _, p := range pinned {
		if r.used+size <= maxCacheBytes {
			break
		}
		e := r.cache[p.ref]
		r.used -= e.size
		r.pinnedBytes -= e.size
		delete(r.cache, p.ref)
	}
	return true
}
