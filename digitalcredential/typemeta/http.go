// Retrieval from the URL in vct: draft-ietf-oauth-sd-jwt-vc-19 §5.3.1, with
// the bounds of §3 and the trust rule of §7.8.

package typemeta

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/pilacorp/go-credential-sdk/digitalcredential/internal/allowlist"
	"github.com/pilacorp/go-credential-sdk/digitalcredential/internal/httpcache"
	"github.com/pilacorp/go-credential-sdk/digitalcredential/internal/safehttp"
	"github.com/pilacorp/go-credential-sdk/jose"
)

const mediaTypeMetadata = "application/json" // §5.3.1

// limits of every retrieval; NewHTTPResolver adds the Follow of
// Config.Redirects.
var limits = safehttp.Limits{Timeout: fetchTimeout, MaxRedirects: maxRedirects, MaxBytes: maxDocumentBytes}

// ErrRedirectNotAllowed: the resolver refused, before sending it, a
// redirect of a vct or extends that Config.Redirects does not follow.
var ErrRedirectNotAllowed = safehttp.ErrNotFollowed

// RedirectPolicy says where the resolver of NewHTTPResolver follows a
// redirect of a vct or extends. The zero value follows one only within the
// origin of that URL. RedirectTo and RedirectAny widen it. A policy never
// changes which vct or extends the resolver recognizes.
type RedirectPolicy struct {
	mode    redirectMode
	origins []string
}

// redirectMode is the kind of a RedirectPolicy; the zero mode follows a
// redirect only within the origin requested.
type redirectMode int

const (
	redirectTo redirectMode = iota + 1
	redirectAny
)

// RedirectTo also follows a redirect to an origin that origins cover, read
// as entries of Config.TrustedPublisherOrigins; one within the origin
// requested is still followed, so there is no policy that follows only the
// origins listed. It does not recognize a vct on those origins, yet each
// one may answer for every vct the resolver recognizes. NewHTTPResolver
// refuses it with no origin, or with an entry TrustedPublisherOrigins would
// refuse.
func RedirectTo(origins ...string) RedirectPolicy {
	return RedirectPolicy{mode: redirectTo, origins: slices.Clone(origins)}
}

// RedirectAny follows a redirect to any https URL, one an open redirect on
// the publisher's server sends included.
func RedirectAny() RedirectPolicy { return RedirectPolicy{mode: redirectAny} }

// rule checks p and returns the rule it stands for.
func (p RedirectPolicy) rule() (allowlist.Redirects, error) {
	switch p.mode {
	case redirectAny:
		return allowlist.RedirectsAny(), nil
	case redirectTo:
		if len(p.origins) == 0 {
			return allowlist.Redirects{}, fmt.Errorf("%w: typemeta: Config.Redirects is RedirectTo with no origin; leave Redirects zero to follow redirects only within the origin requested", jose.ErrInvalidArgument)
		}
		for i, e := range p.origins {
			if why := allowlist.Check(e, allowlist.Hints{All: "use RedirectAny()"}); why != "" {
				return allowlist.Redirects{}, fmt.Errorf("%w: typemeta: Config.Redirects RedirectTo[%d] %s", jose.ErrInvalidArgument, i, why)
			}
		}
		return allowlist.RedirectsTo(p.origins), nil
	}
	return allowlist.Redirects{}, nil
}

// trustHints complete the texts of a refused entry of
// TrustedPublisherOrigins.
var trustHints = allowlist.Hints{
	All:   "leave Config.TrustedPublisherOrigins empty",
	Finer: "list the origin and refuse the other vct in a Resolver that wraps this one",
}

// Config configures NewHTTPResolver.
type Config struct {
	// TrustedPublisherOrigins lists the origins whose Type Metadata this
	// application recognizes (§7.8). Empty, it recognizes every https
	// publisher. Entries read as for
	// issuermeta.Config.TrustedIssuerOrigins: "https://host", with or without
	// a port and a final "/", covers every URL of that origin, and
	// "https://*.host" every URL of a subdomain of host; any other entry, one
	// with a path included, is refused. TrustedPublisherOrigins is matched
	// against vct, the URL the credential names, or the extends of a
	// document.
	//
	// The list does not judge redirects; Redirects does.
	TrustedPublisherOrigins []string
	// Redirects says where a redirect of a vct or extends may lead. The
	// zero value keeps it on the origin of the URL requested: the
	// credential or the extending document chooses the URL, and an open
	// redirect on the publisher's server could otherwise hand the
	// retrieval to another origin. Integrity does not lift this: the
	// issuer, or the author of the extending document, writes the hash as
	// well as the URL, while the origin is what the application recognizes.
	// Draft 19 §3 leaves following redirects to the Consumer. A refused
	// redirect is not sent, and the failure, never cached, wraps
	// ErrRedirectNotAllowed.
	Redirects RedirectPolicy
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
	trusted allowlist.List
	limits  safehttp.Limits
	client  *http.Client
	noCache bool
	now     func() time.Time

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
// vct from that URL (draft 19 §5.3.1). cfg is copied, the lists included.
// An entry of TrustedPublisherOrigins, or of a RedirectTo in Redirects, is
// jose.ErrInvalidArgument when it is not an https origin "https://host" or
// "https://*.host", each with an optional port and final "/": "*", a path,
// query, fragment or userinfo is refused, and so is a "*" anywhere else, a
// host that is not ASCII or has an empty label, such as a final ".", a host
// with ":" or "[" that is not an IPv6 address or has "*." before one, or a
// port with a leading zero or out of range. So is a RedirectTo with no
// origin.
//
// Metadata returns ErrNotFound, without a request, when ref.VCT is not an
// https URL with a host, has userinfo or a fragment, or no entry of
// TrustedPublisherOrigins covers its origin. Otherwise it sends a GET to
// exactly ref.VCT: https on every redirect, at most 3 redirects, each one
// that Config.Redirects follows from ref.VCT, 5 seconds, a 2xx
// application/json response of at most 256 KiB (§3); a 404 is ErrNotFound,
// a refused redirect ErrRedirectNotAllowed, any other failure an error that
// matches no sentinel of this package, its cause wrapped. The cache counts
// an estimated 4 MiB and is keyed by the Ref. With ref.Integrity, a
// document is cached only when it passes CheckIntegrity, and then with no
// expiry (§5.3.4); one that fails is returned uncached for Load to reject.
// Without, it is reused as RFC 9111 §4.2 and §5.2 allow, for at most 24
// hours. When the 4 MiB are full, expired entries go first, then those with
// no expiry, oldest first. A failure is never cached. It is safe for
// concurrent use. Error texts quote no vct or URL.
func NewHTTPResolver(cfg Config) (Resolver, error) {
	for i, e := range cfg.TrustedPublisherOrigins {
		if why := allowlist.Check(e, trustHints); why != "" {
			return nil, fmt.Errorf("%w: typemeta: Config.TrustedPublisherOrigins[%d] %s", jose.ErrInvalidArgument, i, why)
		}
	}
	redirects, err := cfg.Redirects.rule()
	if err != nil {
		return nil, err
	}
	l := limits
	l.Follow = redirects.Follows
	r := &httpResolver{
		trusted: allowlist.New(cfg.TrustedPublisherOrigins),
		limits:  l,
		client:  cfg.HTTPClient,
		noCache: cfg.DisableCache,
		now:     time.Now,
		cache:   map[Ref]cacheEntry{},
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
	if !r.trusted.Covers(u) {
		return nil, fmt.Errorf("%w: typemeta: the origin of vct is not covered by Config.TrustedPublisherOrigins; list it there to trust it", ErrNotFound)
	}
	if doc, ok := r.cached(ref); ok {
		return doc, nil
	}
	// RFC 9111 §4.2.3: age is measured from the time the request was sent.
	sent := r.now()
	doc, fresh, err := httpcache.Get(ctx, r.client, ref.VCT, []string{mediaTypeMetadata}, r.limits, maxCacheLifetime)
	if err != nil {
		if se := (*safehttp.StatusError)(nil); errors.As(err, &se) && se.Code == http.StatusNotFound {
			return nil, fmt.Errorf("%w: typemeta: the publisher answered 404", ErrNotFound)
		}
		if errors.Is(err, safehttp.ErrNotFollowed) {
			return nil, fmt.Errorf("typemeta: fetching the Type Metadata: %w: the redirect leaves the origin of the URL requested for a target Config.Redirects does not allow; the publisher must serve it from that origin, or the verifier allows the target with RedirectTo", err)
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
