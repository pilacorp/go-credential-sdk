package processor

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sync"
	"syscall"
	"time"

	"github.com/piprate/json-gold/ld"
)

// Bounds on remote @context fetches. A document under verification names its
// own context URLs, and canonicalization runs before the signature check, so
// all of these face an unauthenticated caller.
const (
	// maxContextBytes is far above any published context: schema.org's, the
	// largest in common use, is about 150 KB.
	maxContextBytes = 1 << 20
	// maxContextRequests counts the HTTP requests of one fetch: redirects, and
	// the Link rel=alternate hops json-gold follows by recursing, which neither
	// a client timeout nor the redirect limit sees. schema.org needs one hop.
	maxContextRequests = 16
	// maxCachedContexts bounds the cache: an attacker can name any number of
	// URLs on a server of their own. A deployment uses tens of contexts.
	maxCachedContexts = 256
	// maxContextLoads bounds the remote context loads of one JSON-LD operation,
	// cached ones included. json-gold's check for a context including itself
	// never fires (it hands the nested parse an empty list), so a context that
	// names itself recurses until `fatal error: stack overflow`.
	maxContextLoads = 1024
	// maxContextLoadTime bounds one JSON-LD operation's remote loads taken
	// together, for a chain of contexts each answering just under the timeout.
	maxContextLoadTime = 30 * time.Second
)

// contextFetchTimeout bounds one fetch: all its requests, each body included.
// It is a var so tests can shorten it.
var contextFetchTimeout = 10 * time.Second

// Failures of a remote @context load. ErrContextLoad is every failed fetch, and
// the others name a refusal of this SDK.
var (
	ErrContextLoad     = ld.NewJsonLdError(ld.LoadingDocumentFailed, "remote context could not be loaded")
	ErrContextAddress  = errors.New("context address is not public")
	ErrContextScheme   = errors.New("context URL is not http or https")
	ErrContextRequests = errors.New("context fetch made too many requests")
	ErrContextOverflow = ld.NewJsonLdError(ld.ErrorCode("context overflow"), "the operation's context budget is used up")
)

// contextLoadError keeps the cause of a failed fetch off the text, which would
// tell the caller whether an address or port answered, and on the chain.
type contextLoadError struct{ cause error }

func (e *contextLoadError) Error() string   { return ErrContextLoad.Error() }
func (e *contextLoadError) Unwrap() []error { return []error{ErrContextLoad, e.cause} }

// SetDocumentLoaderHTTPClient replaces the HTTP client that fetches remote
// @context documents and empties the context cache. It is a test hook, for
// suites that serve custom contexts from an httptest server on 127.0.0.1:
// client's own transport decides what it may reach, so the refusal of
// non-public addresses does not apply to it. The time, size and scheme limits
// still do. nil restores the default client, which production code never needs
// to set.
func SetDocumentLoaderHTTPClient(client *http.Client) {
	if client == nil {
		client = publicOnlyClient
	}
	defaultDocumentLoader.fallback.Store(newCachingDocumentLoader(client))
}

// cachingDocumentLoader fetches contexts and caches them. The lock is never
// held across a fetch, so a slow URL holds up neither other URLs nor readers.
type cachingDocumentLoader struct {
	client *http.Client

	mu   sync.RWMutex
	docs map[string]*ld.RemoteDocument
}

func newCachingDocumentLoader(client *http.Client) *cachingDocumentLoader {
	return &cachingDocumentLoader{client: client, docs: make(map[string]*ld.RemoteDocument)}
}

// LoadDocument implements ld.DocumentLoader. Every caller gets its own copy:
// json-gold can mutate a context it is given, which is what the bundled
// contexts are re-parsed on each call to avoid.
func (l *cachingDocumentLoader) LoadDocument(rawURL string) (*ld.RemoteDocument, error) {
	l.mu.RLock()
	doc, cached := l.docs[rawURL]
	l.mu.RUnlock()
	if cached {
		return cloneRemoteDocument(doc), nil
	}

	doc, err := l.fetch(rawURL)
	if err != nil {
		return nil, &contextLoadError{cause: err}
	}

	entry := cloneRemoteDocument(doc)
	l.mu.Lock()
	if len(l.docs) >= maxCachedContexts {
		// Evict rather than stop caching, so filling the cache once does not
		// leave every later context uncached.
		for u := range l.docs {
			delete(l.docs, u)
			break
		}
	}
	l.docs[rawURL] = entry
	l.mu.Unlock()
	return doc, nil
}

func cloneRemoteDocument(doc *ld.RemoteDocument) *ld.RemoteDocument {
	clone := *doc
	clone.Document = ld.CloneDocument(doc.Document)
	return &clone
}

func (l *cachingDocumentLoader) fetch(rawURL string) (*ld.RemoteDocument, error) {
	// ld.DefaultDocumentLoader opens anything else as a local file.
	if !isHTTPURL(rawURL) {
		return nil, ErrContextScheme
	}

	ctx, cancel := context.WithTimeout(context.Background(), contextFetchTimeout)
	defer cancel()

	next := l.client.Transport
	if next == nil {
		next = http.DefaultTransport
	}
	client := *l.client
	client.Transport = &boundedTransport{ctx: ctx, next: next}
	return ld.NewDefaultDocumentLoader(&client).LoadDocument(rawURL)
}

func isHTTPURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https")
}

// boundedTransport applies the limits of one fetch to each of its requests.
// json-gold builds its requests without a context and recurses on Link
// rel=alternate, so the transport is the one place every hop passes through.
type boundedTransport struct {
	ctx      context.Context
	next     http.RoundTripper
	requests int
}

// RoundTrip implements http.RoundTripper.
func (t *boundedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.requests++; t.requests > maxContextRequests {
		return nil, ErrContextRequests
	}
	res, err := t.next.RoundTrip(req.WithContext(t.ctx))
	if err != nil {
		return nil, err
	}
	// json-gold loads an alternate itself, past the scheme check in fetch.
	for _, link := range ld.ParseLinkHeader(res.Header.Get("Link"))["alternate"] {
		if link["type"] == ld.ApplicationJSONLDType && !isHTTPURL(ld.Resolve(req.URL.String(), link["target"])) {
			res.Body.Close()
			return nil, ErrContextScheme
		}
	}
	res.Body = http.MaxBytesReader(nil, res.Body, maxContextBytes)
	return res, nil
}

// contextBudget is the loader of one JSON-LD operation: it stops the recursion
// and the chains described at maxContextLoads and maxContextLoadTime. Bundled
// contexts are free: they are local and include no remote context.
type contextBudget struct {
	loads    int
	deadline time.Time
}

func newContextBudget() *contextBudget {
	return &contextBudget{deadline: time.Now().Add(maxContextLoadTime)}
}

// LoadDocument implements ld.DocumentLoader.
func (b *contextBudget) LoadDocument(rawURL string) (*ld.RemoteDocument, error) {
	if _, bundled := wellKnownContexts[rawURL]; !bundled {
		if b.loads++; b.loads > maxContextLoads || time.Now().After(b.deadline) {
			return nil, ErrContextOverflow
		}
	}
	return defaultDocumentLoader.LoadDocument(rawURL)
}

// publicOnlyClient is the client of every context fetch unless a test replaced
// it. A proxy would connect on its behalf and hide the address, so it uses none.
var publicOnlyClient = newPublicOnlyClient()

// newPublicOnlyClient keeps its dial and handshake bounds apart from
// contextFetchTimeout: net/http keeps dialing after a request is canceled.
func newPublicOnlyClient() *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second, Control: refuseNonPublic}
	return &http.Client{Transport: &http.Transport{
		DialContext:            dialer.DialContext,
		TLSHandshakeTimeout:    5 * time.Second,
		ForceAttemptHTTP2:      true,
		MaxIdleConns:           100,
		IdleConnTimeout:        90 * time.Second,
		MaxResponseHeaderBytes: 64 << 10,
	}}
}

// refuseNonPublic is the dialer's Control, so it judges the address actually
// connected to: after DNS resolution, on every redirect and every attempt.
func refuseNonPublic(_, address string, _ syscall.RawConn) error {
	// An address that is not ip:port is refused too: the dialer passes an empty
	// host unresolved, and dialing ":443" reaches the local host.
	ap, err := netip.ParseAddrPort(address)
	if err != nil || !isPublicAddr(ap.Addr()) {
		return ErrContextAddress
	}
	return nil
}

// nonPublicPrefixes is the table of digitalcredential/internal/safehttp, which
// this module cannot import: the IANA special-purpose registries' entries that
// are not globally reachable, plus multicast and deprecated site-local.
var nonPublicPrefixes = func() []netip.Prefix {
	var prefixes []netip.Prefix
	for _, p := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
		"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
		"192.88.99.2/32", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
		"203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
		"64:ff9b:1::/48", "100::/64", "100:0:0:1::/64", "2001::/23", "2001:db8::/32",
		"3fff::/20", "5f00::/16", "fc00::/7", "fe80::/10", "fec0::/10", "ff00::/8",
	} {
		prefixes = append(prefixes, netip.MustParsePrefix(p))
	}
	return prefixes
}()

var (
	ipv4CompatiblePrefix = netip.MustParsePrefix("::/96")
	nat64Prefix          = netip.MustParsePrefix("64:ff9b::/96")
	sixToFourPrefix      = netip.MustParsePrefix("2002::/16")
)

// isPublicAddr reports whether ip may be connected to. An IPv6 address that
// carries an IPv4 address is judged by that IPv4 address.
func isPublicAddr(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	// Prefix.Contains never matches an address with a zone.
	ip = ip.WithZone("")
	b := ip.As16()
	switch {
	case ip.Is4In6():
		ip = ip.Unmap()
	case ipv4CompatiblePrefix.Contains(ip), nat64Prefix.Contains(ip):
		ip = netip.AddrFrom4([4]byte(b[12:16]))
	case sixToFourPrefix.Contains(ip):
		ip = netip.AddrFrom4([4]byte(b[2:6]))
	}
	for _, p := range nonPublicPrefixes {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}
