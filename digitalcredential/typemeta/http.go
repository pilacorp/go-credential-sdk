// Retrieval from the URL in vct: draft-ietf-oauth-sd-jwt-vc-19 §5.3.1, with
// the bounds of §3 and the trust rule of §7.8.

package typemeta

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/pilacorp/go-credential-sdk/digitalcredential/internal/allowlist"
	"github.com/pilacorp/go-credential-sdk/digitalcredential/internal/httpcache"
	"github.com/pilacorp/go-credential-sdk/digitalcredential/internal/safehttp"
	"github.com/pilacorp/go-credential-sdk/jose"
)

const mediaTypeMetadata = "application/json" // §5.3.1

var limits = safehttp.Limits{Timeout: fetchTimeout, MaxRedirects: maxRedirects, MaxBytes: maxDocumentBytes}

// Config configures NewHTTPResolver.
type Config struct {
	// Allowed lists the publishers whose Type Metadata this application
	// trusts (§7.8); it is required. An entry ending in "/" covers every vct
	// that starts with it, except one whose path has a "." or ".." segment;
	// any other entry covers the vct equal to it. Matching is byte for byte,
	// as for issuermeta.Config.Allowed. Allowed is matched against vct, the
	// URL the credential names, or the extends of a document, and not
	// against the redirects of its retrieval (https, at most 3, §3). An entry
	// equal to that URL names a document the application trusts, so its
	// server's redirects are followed to any https host. Under an entry
	// ending in "/" the credential or the extending document chooses the
	// path, and an open redirect on the publisher's server would let another
	// origin supply the document. Integrity does not prevent it: the issuer,
	// or the author of the extending document, writes the hash as well as
	// the path, while Allowed trusts the publisher. There redirects are
	// followed only within the origin of that URL.
	Allowed []string
	// AllowCrossOriginRedirects follows redirects to another origin also for
	// a URL that only an entry ending in "/" covers. Off, such a redirect
	// fails the retrieval before it is sent, and the failure is not cached;
	// listing that URL in Allowed also lets its redirects through. Draft 19
	// §3 leaves following redirects to the Consumer.
	AllowCrossOriginRedirects bool
	// HTTPClient retrieves the documents; nil uses a client that refuses
	// addresses that are not globally reachable (§7.1). A client passed here
	// is trusted code: the URL checks and the limits still apply, but the
	// address check exists only in the default transport.
	HTTPClient *http.Client
	// DisableCache makes every call retrieve the document again and stores
	// nothing (RFC 9111 §2).
	DisableCache bool
}

// httpResolver is the Resolver of NewHTTPResolver.
type httpResolver struct {
	allowed     allowlist.List
	crossOrigin bool
	client      *http.Client
	noCache     bool
	now         func() time.Time

	mu    sync.Mutex
	cache map[Ref]cacheEntry
	used  int // bytes of the cached entries, as estimated by store
	// pinnedBytes is the part of used held by entries with no expiry.
	pinnedBytes int
	// purgeAt is no later than the earliest expiry in cache, zero when
	// unknown: before it, a full cache holds no expired entry to drop.
	purgeAt time.Time
}

// NewHTTPResolver returns a Resolver that retrieves the document of an https
// vct from that URL (draft 19 §5.3.1). cfg is copied, Allowed included. An
// empty Allowed, or an entry that does not start with https:// (the scheme
// in any case), is jose.ErrInvalidArgument: Type Metadata is only as
// trustworthy as its publisher (§7.8).
//
// Metadata returns ErrNotFound, without a request, when ref.VCT is not an
// https URL with a host, has userinfo or a fragment, or no entry of Allowed
// covers it. Otherwise it sends a GET to exactly ref.VCT: https on every
// redirect, at most 3 redirects, within the origin of ref.VCT when no entry
// equals it and AllowCrossOriginRedirects is off, 5 seconds, a 2xx
// application/json response of at most 256 KiB (§3); a 404 is ErrNotFound,
// any other failure an error that matches no sentinel of this package, its
// cause wrapped. The cache
// counts an estimated 4 MiB and is keyed by the Ref. With ref.Integrity, a
// document is cached only when it passes CheckIntegrity, and then with no
// expiry (§5.3.4); one that fails is returned uncached for Load to reject.
// Without, it is reused as RFC 9111 §4.2 and §5.2 allow, for at most 24
// hours. When the 4 MiB are full, expired entries go first, then those with
// no expiry, oldest first. A failure is never cached. It is safe for concurrent use.
// Error texts quote no vct or URL.
func NewHTTPResolver(cfg Config) (Resolver, error) {
	if len(cfg.Allowed) == 0 {
		return nil, fmt.Errorf(`%w: typemeta: Config.Allowed is empty; list the publishers this application trusts, or "https://" for any https publisher (draft-ietf-oauth-sd-jwt-vc-19 §7.8)`, jose.ErrInvalidArgument)
	}
	for i, e := range cfg.Allowed {
		if !allowlist.ValidEntry(e) {
			return nil, fmt.Errorf(`%w: typemeta: Config.Allowed[%d] does not start with https://; list https publishers, or "https://" for any https publisher`, jose.ErrInvalidArgument, i)
		}
	}
	r := &httpResolver{
		allowed:     allowlist.New(cfg.Allowed),
		crossOrigin: cfg.AllowCrossOriginRedirects,
		client:      cfg.HTTPClient,
		noCache:     cfg.DisableCache,
		now:         time.Now,
		cache:       map[Ref]cacheEntry{},
	}
	if r.client == nil {
		r.client = safehttp.NewClient()
	}
	return r, nil
}

func (r *httpResolver) Metadata(ctx context.Context, ref Ref) ([]byte, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: typemeta: nil context", jose.ErrInvalidArgument)
	}
	u, err := url.Parse(ref.VCT)
	if err != nil || !safehttp.HTTPSURL(u) || strings.Contains(ref.VCT, "#") {
		return nil, fmt.Errorf("%w: typemeta: vct is not an https URL with a host, without userinfo or fragment (draft-ietf-oauth-sd-jwt-vc-19 §5.3.1)", ErrNotFound)
	}
	if ok, _ := r.allowed.Covers(ref.VCT, u); !ok {
		return nil, fmt.Errorf("%w: typemeta: vct is not covered by the allowed publishers", ErrNotFound)
	}
	if doc, ok := r.cached(ref); ok {
		return doc, nil
	}
	// RFC 9111 §4.2.3: age is measured from the time the request was sent.
	sent := r.now()
	l := limits
	// A URL listed exactly is one the application named; one under an entry
	// ending in "/" is a path the credential or a document chose.
	l.SameOrigin = !r.crossOrigin && !r.allowed.Names(ref.VCT)
	doc, fresh, err := httpcache.Get(ctx, r.client, ref.VCT, []string{mediaTypeMetadata}, l, maxCacheLifetime)
	if err != nil {
		if se := (*safehttp.StatusError)(nil); errors.As(err, &se) && se.Code == http.StatusNotFound {
			return nil, fmt.Errorf("%w: typemeta: the publisher answered 404", ErrNotFound)
		}
		if errors.Is(err, safehttp.ErrCrossOrigin) {
			return nil, fmt.Errorf("typemeta: fetching the Type Metadata: %w under an Allowed entry ending in \"/\"; list the vct in Config.Allowed or set Config.AllowCrossOriginRedirects", err)
		}
		return nil, fmt.Errorf("typemeta: fetching the Type Metadata: %w", err)
	}
	switch {
	case ref.Integrity == "":
		r.store(ref, doc, sent, sent.Add(fresh))
	case CheckIntegrity(doc, ref.Integrity) == nil:
		r.store(ref, doc, sent, time.Time{})
	}
	return doc, nil
}
