// The Checker's cache of verified Status Lists: draft-ietf-oauth-status-list-21
// §8.3 step 4d and §13.7.

package statuslist

import (
	"strings"
	"time"
)

type cacheKey struct{ iss, uri string }

type cacheEntry struct {
	list    *List // never handed out: Status returns values only
	iat     time.Time
	expires time.Time
	size    int
}

// cached returns the list cached for key, or nil when there is none or it
// has expired.
func (c *Checker) cached(key cacheKey) *List {
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.cache[key]; ok && now.Before(e.expires) {
		return e.list
	}
	return nil
}

// store caches l, from a token issued at iat, for key until expires. It
// replaces an entry of the same key, unless that entry is live and comes
// from a newer token: fetches can finish out of order, and iat is the only
// signed order between two tokens of one list (draft 21 §5.1, §13.7). An
// entry counts the memory it holds, the capacity of the byte array and the
// key. When the cache is full, expired entries are dropped; if there is still
// no room, l is not cached, which costs a fetch, never a wrong answer.
func (c *Checker) store(key cacheKey, l *List, iat, expires time.Time) {
	now := c.now()
	if !now.Before(expires) {
		return
	}
	size := cap(l.b) + len(key.iss) + len(key.uri)
	c.mu.Lock()
	defer c.mu.Unlock()
	if old, ok := c.cache[key]; ok {
		if now.Before(old.expires) && old.iat.After(iat) {
			return
		}
		c.used -= old.size
		delete(c.cache, key)
	}
	if c.used+size > maxCacheBytes {
		for k, e := range c.cache {
			if !now.Before(e.expires) {
				c.used -= e.size
				delete(c.cache, k)
			}
		}
		if c.used+size > maxCacheBytes {
			return
		}
	}
	// Cloned so the budget counts what the entry holds, even when the caller
	// passed substrings of a larger buffer.
	key = cacheKey{iss: strings.Clone(key.iss), uri: strings.Clone(key.uri)}
	c.cache[key] = cacheEntry{list: l, iat: iat, expires: expires, size: size}
	c.used += size
}
