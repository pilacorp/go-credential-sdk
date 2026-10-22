package statuslist

import (
	clist "container/list"
	"sync"
	"time"
)

// listCache keeps verified lists until their expiry, bounded by the total size
// of the lists it holds (a list can be up to MaxListBytes), evicting the least
// recently used first. Failures are never stored. Safe for concurrent use.
type listCache struct {
	mu       sync.Mutex
	maxBytes int64
	used     int64
	byKey    map[string]*clist.Element
	order    *clist.List // front = most recently used
}

type cacheEntry struct {
	key     string
	list    *List
	expires time.Time
	size    int64
}

func newListCache(maxBytes int64) *listCache {
	return &listCache{maxBytes: maxBytes, byKey: map[string]*clist.Element{}, order: clist.New()}
}

// get returns the list stored under key if it has not expired at now.
func (c *listCache) get(key string, now time.Time) (*List, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.byKey[key]
	if !ok {
		return nil, false
	}
	e := el.Value.(*cacheEntry)
	if !now.Before(e.expires) {
		c.remove(el)
		return nil, false
	}
	c.order.MoveToFront(el)
	return e.list, true
}

// put stores l under key until expires. A list larger than the whole cache is
// not stored.
func (c *listCache) put(key string, l *List, expires time.Time) {
	size := int64(len(l.data) + len(key))
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.byKey[key]; ok {
		c.remove(el)
	}
	if size > c.maxBytes {
		return
	}
	for c.used+size > c.maxBytes {
		c.remove(c.order.Back())
	}
	c.byKey[key] = c.order.PushFront(&cacheEntry{key: key, list: l, expires: expires, size: size})
	c.used += size
}

func (c *listCache) remove(el *clist.Element) {
	e := el.Value.(*cacheEntry)
	c.order.Remove(el)
	delete(c.byKey, e.key)
	c.used -= e.size
}
