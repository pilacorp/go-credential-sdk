// Package issuermeta resolves the keys of an issuer from its JWT VC Issuer
// Metadata, the first key-resolution mechanism of
// draft-ietf-oauth-sd-jwt-vc-19 §2.5: for an https iss, the metadata at the
// location of §4 and §4.1, its issuer identical to iss (§4.2, §4.3), and the
// JWK Set it holds in jwks or references by jwks_uri (§4.2; RFC 7517 §5). A
// Resolver is an issuerkey.Resolver, for the Verifier of package dc and for
// a statuslist.Checker.
//
// Every retrieval follows §3: https only, on every redirect too, at most 3
// redirects, 5 seconds and 64 KiB each, and a 2xx response of the expected
// media type (application/json for the metadata, application/jwk-set+json or
// application/json for a JWK Set, RFC 7517 §8.5). A cache miss makes at most
// two retrievals. Responses are cached as RFC 9111 §4.2 and §5.2 allow, for
// at most 24 hours and no longer than the least fresh response of the
// retrieval, redirects included; a failure is never cached.
//
// The default client refuses addresses that are not globally reachable, but
// hosts reachable only inside the deployment's own network are known to no
// registry: the deployment's egress policy must block them (§7.1). A client
// passed in Config.HTTPClient is trusted code. No other mechanism of §2.5,
// such as x5c, and no legacy metadata location is tried.
package issuermeta

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/pilacorp/go-credential-sdk/digitalcredential/internal/safehttp"
	"github.com/pilacorp/go-credential-sdk/digitalcredential/issuerkey"
	"github.com/pilacorp/go-credential-sdk/jose"
	"github.com/pilacorp/go-credential-sdk/jose/jwk"
	"github.com/pilacorp/go-credential-sdk/jose/jws"
)

// Fixed limits of the Resolver; every value is SDK policy. Draft 19 §3 asks
// for redirect, time and size bounds without a number.
const (
	mediaTypeMetadata = "application/json" // §4.2
	wellKnown         = "/.well-known/jwt-vc-issuer"
	fetchTimeout      = 5 * time.Second
	maxRedirects      = 3
	maxBodyBytes      = 64 << 10 // about 500 EC JWKs
	maxCacheLifetime  = 24 * time.Hour
	maxCacheBytes     = 4 << 20
)

// mediaTypesJWKSet: RFC 7517 §8.5 registers application/jwk-set+json, and
// draft 19 does not name one for jwks_uri, so a JWK Set served as JSON is
// accepted too.
var mediaTypesJWKSet = []string{"application/jwk-set+json", "application/json"}

var limits = safehttp.Limits{Timeout: fetchTimeout, MaxRedirects: maxRedirects, MaxBytes: maxBodyBytes}

// Resolver returns the signing keys an issuer publishes in its JWT VC Issuer
// Metadata. Construct it with NewResolver and share one instance: the cache
// and the default client's connections belong to it. It is safe for
// concurrent use.
//
// The cache counts 4 MiB, estimated from the keys and iss it holds, not
// total heap. When live entries fill it, new answers are not cached until one
// expires. With the entry "https://", anyone who can serve https metadata
// can fill it, which costs legitimate issuers a retrieval on every call
// until entries expire, never a wrong key. There is no single-flight:
// concurrent misses on one iss each fetch.
type Resolver struct {
	allowed []string
	client  *http.Client
	noCache bool
	now     func() time.Time

	mu    sync.Mutex
	cache map[string]cacheEntry
	used  int // bytes of the cached entries, as estimated by store
	// purgeAt is no later than the earliest expiry in cache, zero when
	// unknown: before it, a full cache holds no expired entry to drop.
	purgeAt time.Time
}

// Config configures NewResolver.
type Config struct {
	// Allowed lists the issuers this verifier trusts, the Relying Party's
	// policy of draft 19 §2.5; it is required. An entry ending in "/" covers
	// every iss that starts with it, except one whose path has a "." or ".."
	// segment (see Keys); any other entry covers the iss equal to it.
	// Matching is byte for byte, so case-sensitive: "https://" covers every
	// iss starting with https:// in lower case.
	Allowed []string
	// HTTPClient retrieves the metadata and JWK Sets; nil uses a client that
	// refuses addresses that are not globally reachable. A deployment behind
	// an egress proxy passes its own.
	//
	// It is trusted code. The URL checks and the limits of the Resolver still
	// judge the URLs requested and the response returned, but the address
	// check and the 64 KiB cap on response headers exist only in the default
	// transport, and the 5-second timeout holds only if its transport honours
	// the request context.
	HTTPClient *http.Client
	// DisableCache makes every call of Keys retrieve the metadata again, and
	// stores nothing: a cache may always choose not to store (RFC 9111 §2).
	// It sends no request directive, so a cache inside HTTPClient still
	// answers as that client is configured.
	DisableCache bool
}

// NewResolver returns a Resolver for cfg, which it copies, Allowed included,
// and does not read again. An empty Allowed is jose.ErrInvalidArgument, and
// so is an entry that does not start with https:// (the scheme in any case):
// it would match no iss or, like "https:/", every one.
func NewResolver(cfg Config) (*Resolver, error) {
	if len(cfg.Allowed) == 0 {
		return nil, fmt.Errorf(`%w: issuermeta: Config.Allowed is empty; list the issuers this verifier trusts, or "https://" for any https issuer`, jose.ErrInvalidArgument)
	}
	for i, e := range cfg.Allowed {
		if len(e) < len("https://") || !strings.EqualFold(e[:len("https://")], "https://") {
			return nil, fmt.Errorf(`%w: issuermeta: Config.Allowed[%d] does not start with https://; list https issuers, or "https://" for any https issuer`, jose.ErrInvalidArgument, i)
		}
	}
	r := &Resolver{
		allowed: slices.Clone(cfg.Allowed),
		client:  cfg.HTTPClient,
		noCache: cfg.DisableCache,
		now:     time.Now,
		cache:   map[string]cacheEntry{},
	}
	if r.client == nil {
		r.client = safehttp.NewClient()
	}
	return r, nil
}

var _ issuerkey.Resolver = (*Resolver)(nil)

// Keys returns the signing keys the metadata of iss publishes. Its outcomes
// are those of issuerkey.Resolver:
//   - the keys, possibly none: each P-256 or secp256k1 JWK of the set that
//     jwk.ToPublicKey accepts, whose kid, if present, is a string, and whose
//     use, alg and key_ops, if present, allow verifying with the curve's alg
//     (RFC 7517 §4.2-4.5, RFC 8725 §3.1); other JWKs are skipped (RFC 7517
//     §5);
//   - an error wrapping issuerkey.ErrIssuerNotSupported, before any request:
//     iss is not an https URL with a host and no query or fragment (§2.5,
//     §4) and no userinfo (RFC 9110 §4.2.4), or no allowed entry covers it.
//     An entry ending in "/" covers no iss whose path, decoded once, has a
//     "." or ".." segment: such a path names a resource outside the entry
//     (RFC 3986 §2.3, §6.2.2.3). Splitting segments at "\" and %2F too, and
//     cutting a segment at ";", is SDK policy: some servers resolve them so;
//   - an error wrapping issuerkey.ErrNoUsableKey: the issuer's server
//     answered, and the metadata or the JWK Set is not valid (§4.2, §4.3,
//     RFC 7517 §4, §5), so it must not be used;
//   - any other error: a retrieval failed (§3), and a later call may
//     succeed. It wraps the cause, such as context.Canceled; an address the
//     default client refuses (draft 19 §7.1) is such an error, and its text
//     names a blocked address; it matches no exported sentinel.
//
// A hit in the cache makes no request and does not look at ctx. A key the
// issuer removes may still verify for up to min(max-age − Age, 24 h) of the
// least fresh response of the retrieval that carried it: the metadata, the
// JWK Set, and every redirect leading to either. A new Resolver starts with
// an empty cache. The returned slice is the caller's; the keys in it are
// shared and must not be modified. Error texts quote no iss, URL, issuer or
// jwks_uri, except that a failed connection's text, cut to 200 characters
// and quoted, can name the host or address dialled.
func (r *Resolver) Keys(ctx context.Context, iss string) ([]issuerkey.PublicKey, error) {
	if r == nil || r.client == nil {
		return nil, fmt.Errorf("%w: issuermeta: Resolver not made by NewResolver", jose.ErrInvalidArgument)
	}
	if ctx == nil {
		return nil, fmt.Errorf("%w: issuermeta: nil context", jose.ErrInvalidArgument)
	}
	if iss == "" {
		return nil, fmt.Errorf("%w: issuermeta: the credential has no iss; issuermeta resolves only https issuers (draft-ietf-oauth-sd-jwt-vc-19 §2.5)", issuerkey.ErrIssuerNotSupported)
	}
	u, metaURL, err := metadataURL(iss)
	if err != nil {
		return nil, err
	}
	if ok, dot := r.covers(iss, u); !ok {
		if dot {
			return nil, fmt.Errorf("%w: issuermeta: iss is not covered by the allowed issuers: an entry ending in / covers no path with a . or .. segment (RFC 3986 §6.2.2.3; reading \\ and %%2F as separators and ignoring ;-parameters are SDK policy); an issuer should not use such a path", issuerkey.ErrIssuerNotSupported)
		}
		return nil, fmt.Errorf("%w: issuermeta: iss is not covered by the allowed issuers", issuerkey.ErrIssuerNotSupported)
	}
	if keys, ok := r.cached(iss); ok {
		return keys, nil
	}
	// RFC 9111 §4.2.3: age is measured from the time the request was sent.
	sent := r.now()
	keys, expires, err := r.fetch(ctx, iss, metaURL, sent)
	if err != nil {
		return nil, err
	}
	r.store(iss, keys, sent, expires)
	return keys, nil
}

// MetadataURL returns the location of the JWT VC Issuer Metadata of iss:
// the well-known string /.well-known/jwt-vc-issuer inserted between the host
// and the path of iss, after every terminating "/" is removed
// (draft-ietf-oauth-sd-jwt-vc-19 §4, §4.1). The host and path are kept as
// iss writes them, percent-encoding included. An issuer publishes its
// metadata there.
//
// It applies no allowed-issuer check and no verifier policy. An error wraps
// issuerkey.ErrIssuerNotSupported: iss is not an https URL with a host and no
// userinfo, query or fragment. Resolver.Keys refuses an iss whose path has .
// or .. segments when an allowed-issuers entry ending in / is what would
// match it (SDK policy); an issuer should not use one.
func MetadataURL(iss string) (string, error) {
	_, s, err := metadataURL(iss)
	return s, err
}

func metadataURL(iss string) (*url.URL, string, error) {
	u, err := url.Parse(iss)
	if err != nil || !safehttp.HTTPSURL(u) {
		return nil, "", fmt.Errorf("%w: issuermeta: iss is not an https URL with a host (draft-ietf-oauth-sd-jwt-vc-19 §4) and no userinfo (RFC 9110 §4.2.4)", issuerkey.ErrIssuerNotSupported)
	}
	// RFC 3986 §3: neither character appears raw in the authority or path,
	// so either one starts a query or fragment, even an empty one.
	if strings.ContainsAny(iss, "?#") {
		return nil, "", fmt.Errorf("%w: issuermeta: iss has a query or fragment, which draft-ietf-oauth-sd-jwt-vc-19 §4 forbids", issuerkey.ErrIssuerNotSupported)
	}
	// Split the raw iss, not u.Path, so the path reaches the server as the
	// issuer wrote it (u.Path would turn %3A into ":").
	rest := iss[strings.Index(iss, "://")+len("://"):]
	authority, path := rest, ""
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		authority, path = rest[:i], rest[i:]
	}
	return u, "https://" + authority + wellKnown + strings.TrimRight(path, "/"), nil
}

// covers reports whether an allowed entry covers iss, u being iss parsed,
// and whether an entry ending in "/" starts iss but the dot rule refused it.
// iss comes from a token not yet verified, so its path is scanned at most
// once, and only when such an entry starts it.
func (r *Resolver) covers(iss string, u *url.URL) (ok, dot bool) {
	for _, e := range r.allowed {
		switch {
		case !strings.HasSuffix(e, "/"):
			if iss == e {
				return true, false
			}
		case dot || !strings.HasPrefix(iss, e):
		case hasDotSegment(u.Path):
			dot = true
		default:
			return true, false
		}
	}
	return false, dot
}

// hasDotSegment reports whether path, already decoded once by url.Parse, has a
// "." or ".." segment. Raw and %2e forms name a resource outside an entry
// ending in "/" (RFC 3986 §2.3, §6.2.2.3); "\" and %2F as separators and ";"
// path parameters are SDK policy: some servers resolve them so, and no issuer
// identifier needs them. Under draft-ietf-oauth-sd-jwt-vc-20 §4 an issuer
// MUST NOT use dot segments at all, and the check would move to metadataURL.
func hasDotSegment(path string) bool {
	for s := range strings.FieldsFuncSeq(path, func(c rune) bool { return c == '/' || c == '\\' }) {
		if s, _, _ = strings.Cut(s, ";"); s == "." || s == ".." {
			return true
		}
	}
	return false
}

// fetch retrieves the metadata of iss, requested at sent, and its JWK Set,
// and returns the keys and when they expire.
func (r *Resolver) fetch(ctx context.Context, iss, metaURL string, sent time.Time) ([]issuerkey.PublicKey, time.Time, error) {
	body, fresh, err := r.get(ctx, metaURL, []string{mediaTypeMetadata})
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("issuermeta: fetching the issuer metadata: %w", err)
	}
	expires := sent.Add(fresh)
	meta, err := jose.DecodeJSONObject(body)
	if err != nil {
		return nil, time.Time{}, contentFault("the issuer metadata is not a JSON object: %w; the issuer must fix it", err)
	}
	if v, ok := meta["issuer"].(string); !ok {
		return nil, time.Time{}, contentFault("the issuer metadata has no string issuer (draft-ietf-oauth-sd-jwt-vc-19 §4.2)")
	} else if v != iss {
		return nil, time.Time{}, contentFault("the issuer metadata names another issuer than the credential's iss; draft-ietf-oauth-sd-jwt-vc-19 §4.3 forbids using it")
	}
	// A member present as null counts as present.
	jwks, hasJWKS := meta["jwks"]
	uri, hasURI := meta["jwks_uri"]
	var set map[string]any
	switch {
	case hasJWKS && hasURI:
		return nil, time.Time{}, contentFault("the issuer metadata has both jwks and jwks_uri (draft-ietf-oauth-sd-jwt-vc-19 §4.2 allows exactly one)")
	case !hasJWKS && !hasURI:
		return nil, time.Time{}, contentFault("the issuer metadata has neither jwks nor jwks_uri (draft-ietf-oauth-sd-jwt-vc-19 §4.2 requires one)")
	case hasJWKS:
		if set, _ = jwks.(map[string]any); set == nil {
			return nil, time.Time{}, contentFault("jwks is not a JSON object (draft-ietf-oauth-sd-jwt-vc-19 §4.2)")
		}
	default:
		// Checked here rather than by safehttp, whose refusal would read as a
		// failed retrieval: this one is a fault of the issuer's document.
		s, _ := uri.(string)
		if u, err := url.Parse(s); err != nil || !safehttp.HTTPSURL(u) {
			return nil, time.Time{}, contentFault("jwks_uri is not an https URL with a host (draft-ietf-oauth-sd-jwt-vc-19 §3, §4.2) and no userinfo (RFC 9110 §4.2.4)")
		}
		sent := r.now()
		body, fresh, err := r.get(ctx, s, mediaTypesJWKSet)
		if err != nil {
			return nil, time.Time{}, fmt.Errorf("issuermeta: fetching the JWK Set: %w", err)
		}
		if e := sent.Add(fresh); e.Before(expires) {
			expires = e
		}
		if set, err = jose.DecodeJSONObject(body); err != nil {
			return nil, time.Time{}, contentFault("the JWK Set from jwks_uri is not a JSON object: %w", err)
		}
	}
	keys, err := signingKeys(set)
	if err != nil {
		return nil, time.Time{}, err
	}
	return keys, expires, nil
}

// get retrieves rawURL through safehttp.Get and returns the body and how
// long, from the time the request was sent, it may be reused: the least
// freshness of the final response and of every redirect leading to it, since
// reusing the answer to rawURL reuses those redirects too (RFC 9111 §4).
func (r *Resolver) get(ctx context.Context, rawURL string, mediaTypes []string) ([]byte, time.Duration, error) {
	c := *r.client
	next := c.CheckRedirect
	fresh := maxCacheLifetime
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		fresh = min(fresh, freshness(req.Response.Header))
		if next != nil {
			return next(req, via)
		}
		return nil
	}
	body, h, err := safehttp.Get(ctx, &c, rawURL, mediaTypes, limits)
	if err != nil {
		return nil, 0, err
	}
	return body, min(fresh, freshness(h)), nil
}

// signingKeys walks the JWK Set set in its order. A JWK this SDK cannot use
// is skipped (RFC 7517 §5); an element that is not a JWK object makes the
// set invalid (RFC 7517 §4: a JWK is a JSON object; draft 19 §3).
func signingKeys(set map[string]any) ([]issuerkey.PublicKey, error) {
	elems, ok := set["keys"].([]any)
	if !ok {
		return nil, contentFault("the JWK Set has no keys array (RFC 7517 §5)")
	}
	keys := []issuerkey.PublicKey{}
	for _, e := range elems {
		m, ok := e.(map[string]any)
		if !ok {
			return nil, contentFault("the JWK Set holds an element that is not a JWK object (RFC 7517 §4)")
		}
		var kid string
		if v, ok := m["kid"]; ok {
			if kid, ok = v.(string); !ok {
				continue
			}
		}
		pub, err := jwk.ToPublicKey(m)
		if err != nil {
			continue
		}
		alg := jws.AlgES256K // RFC 8812 §3.2
		if k, ok := pub.(*ecdsa.PublicKey); ok && k.Curve == elliptic.P256() {
			alg = jws.AlgES256 // RFC 7518 §3.4
		}
		if !signingKey(m, alg) {
			continue
		}
		keys = append(keys, issuerkey.PublicKey{KID: kid, Public: pub})
	}
	return keys, nil
}

// signingKey reports whether JWK m may verify an Issuer-signed JWT signed
// with alg. RFC 7517 §4.3 leaves to the application which of use and key_ops
// it reads; this resolver reads both, and alg, and skips a key marked for
// another use or algorithm (RFC 7517 §4.2-4.4; RFC 8725 §3.1). A member of
// the wrong JSON type skips the key too. jwk.ToPublicKey already refuses the
// same values on secp256k1 (RFC 8812 §3.2).
func signingKey(m map[string]any, alg string) bool {
	if v, ok := m["use"]; ok && v != "sig" {
		return false
	}
	if v, ok := m["alg"]; ok && v != alg {
		return false
	}
	if v, ok := m["key_ops"]; ok {
		ops, _ := v.([]any)
		if !slices.Contains(ops, any("verify")) {
			return false
		}
	}
	return true
}

// contentFault is the error of a metadata document or JWK Set that must not
// be used: it wraps issuerkey.ErrNoUsableKey, and the arguments, such as a
// jose.ErrMalformed, with %w.
func contentFault(format string, a ...any) error {
	return fmt.Errorf("%w: issuermeta: "+format, append([]any{issuerkey.ErrNoUsableKey}, a...)...)
}
