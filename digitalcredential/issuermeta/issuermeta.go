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
// retrieval, redirects included; a failure is never cached. By default every
// redirect, of the metadata and of jwks_uri, stays on the origin of the URL
// requested, whatever Config.TrustedIssuerOrigins holds: the credential
// chooses the path of iss, and an open redirect on the issuer's server
// could otherwise let another server supply the keys of that iss, even
// when the caller checks the iss itself. Draft 19 §3 leaves following
// redirects to the Consumer; Config.Redirects widens the default.
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
	"github.com/pilacorp/go-credential-sdk/digitalcredential/internal/uri"
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

// limits of every retrieval; NewResolver adds the Follow of Config.Redirects.
var limits = safehttp.Limits{Timeout: fetchTimeout, MaxRedirects: maxRedirects, MaxBytes: maxBodyBytes}

// The causes of a failed retrieval of the metadata or of the JWK Set that
// Keys itself finds. An error of Keys wraps one when it applies, and so does
// an error of Verify through it. Package typemeta exports the same values.
var (
	// ErrRedirectNotAllowed: Keys refused, before sending it, a redirect
	// that Config.Redirects does not follow.
	ErrRedirectNotAllowed = safehttp.ErrNotFollowed
	// ErrRedirectTargetNotAllowed: Keys refused, before sending it, a
	// redirect to a URL that is not https with a host and no userinfo,
	// whatever Config.Redirects allows. It is distinct from
	// ErrRedirectNotAllowed.
	ErrRedirectTargetNotAllowed = safehttp.ErrRedirectTargetNotAllowed
	// ErrTooManyRedirects: a retrieval met more than 3 redirects.
	ErrTooManyRedirects = safehttp.ErrTooManyRedirects
	// ErrContentTypeNotAccepted: the final response is not application/json
	// for the metadata (§4.2), nor application/jwk-set+json or
	// application/json for the JWK Set.
	ErrContentTypeNotAccepted = safehttp.ErrContentTypeNotAccepted
	// ErrBodyTooLarge: the body of the final response is over 64 KiB.
	ErrBodyTooLarge = safehttp.ErrBodyTooLarge
	// ErrAddressBlocked: the default client refused to connect to an
	// address that is not globally reachable (§7.1). A Config.HTTPClient
	// has its own rules.
	ErrAddressBlocked = safehttp.ErrBlockedAddress
)

// StatusError: the final response of a retrieval has a status that is not
// 2xx, held in Code. An error of Keys or Verify gives it to errors.As. It
// is the same type as typemeta.StatusError, so one errors.As target matches
// both.
type StatusError = safehttp.StatusError

// RedirectPolicy says where Keys follows a redirect of the metadata or of
// jwks_uri. The zero value follows one only within the origin of the URL
// requested: the metadata URL built from iss, or jwks_uri. RedirectTo and
// RedirectAny widen it. A policy never changes which iss the Resolver trusts,
// nor which origin jwks_uri may name: the metadata chooses jwks_uri, and only
// its redirects are judged.
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

// RedirectTo also follows a redirect to an origin that origins cover, read as
// entries of Config.TrustedIssuerOrigins; one within the origin requested is
// still followed, so there is no policy that follows only the origins listed.
// It does not trust an iss on those origins, yet each one may answer for
// every iss the Resolver trusts. NewResolver refuses it with no origin, or
// with an entry TrustedIssuerOrigins would refuse.
func RedirectTo(origins ...string) RedirectPolicy {
	return RedirectPolicy{mode: redirectTo, origins: slices.Clone(origins)}
}

// RedirectAny follows a redirect to any https URL, one an open redirect on
// the issuer's server sends included.
func RedirectAny() RedirectPolicy { return RedirectPolicy{mode: redirectAny} }

// rule checks p and returns the rule it stands for.
func (p RedirectPolicy) rule() (allowlist.Redirects, error) {
	switch p.mode {
	case redirectAny:
		return allowlist.RedirectsAny(), nil
	case redirectTo:
		if len(p.origins) == 0 {
			return allowlist.Redirects{}, fmt.Errorf("%w: issuermeta: Config.Redirects is RedirectTo with no origin; leave Redirects zero to follow redirects only within the origin requested", jose.ErrInvalidArgument)
		}
		for i, e := range p.origins {
			if why := allowlist.Check(e, allowlist.Hints{All: "use RedirectAny()"}); why != "" {
				return allowlist.Redirects{}, fmt.Errorf("%w: issuermeta: Config.Redirects RedirectTo[%d] %s", jose.ErrInvalidArgument, i, why)
			}
		}
		return allowlist.RedirectsTo(p.origins), nil
	}
	return allowlist.Redirects{}, nil
}

// Resolver returns the signing keys an issuer publishes in its JWT VC Issuer
// Metadata. Construct it with NewResolver and share one instance: the cache
// and the default client's connections belong to it. It is safe for
// concurrent use.
//
// The cache counts 4 MiB, estimated from the keys and iss it holds, not
// total heap. When live entries fill it, new answers are not cached until one
// expires. With an empty TrustedIssuerOrigins, anyone who can serve
// https metadata can fill it, which costs legitimate issuers a retrieval on
// every call until entries expire, never a wrong key. There is no single-flight:
// concurrent misses on one iss each fetch.
type Resolver struct {
	trusted allowlist.List
	limits  safehttp.Limits
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
	// TrustedIssuerOrigins lists the origins whose issuers this verifier
	// trusts, the Relying Party's policy of draft 19 §2.5, in the style of
	// CORS origins. Empty, it trusts every https issuer, and the caller
	// judges the iss of a verified credential itself.
	// An entry "https://host", with or without a port and a final "/",
	// covers every iss of that origin, and "https://*.host" every iss of an
	// origin whose host is a subdomain of host, the host in any ASCII case
	// and the default port implied. Any other entry is refused, one with a
	// path included: the metadata of every iss sits under /.well-known/ at
	// the root of its origin (§4, §4.1, RFC 8615 §3), so that origin's server
	// answers for every issuer it hosts. To trust some issuers of a shared
	// origin, list the origin and pass those issuers to Verify with
	// WithAcceptedIssuers. The list does not judge redirects; Redirects does.
	TrustedIssuerOrigins []string
	// Redirects says where a redirect of the metadata or of jwks_uri may
	// lead; the zero value keeps it on the origin of the URL requested. A
	// refused redirect is not sent, and the failure wraps
	// ErrRedirectNotAllowed.
	Redirects RedirectPolicy
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

// NewResolver returns a Resolver for cfg, which it copies, the lists
// included, and does not read again. An entry of TrustedIssuerOrigins, or of
// a RedirectTo in Redirects, is jose.ErrInvalidArgument when it is not an
// https origin "https://host" or "https://*.host", each with an optional
// port and final "/": "*", a path, query, fragment or userinfo is refused,
// and so is a "*" anywhere else, a host that is not ASCII or has an empty
// label, such as a final ".", a host with ":" or "[" that is not an IPv6
// address or has "*." before one, or a port with a leading zero or out of
// range. So is a RedirectTo with no origin.
func NewResolver(cfg Config) (*Resolver, error) {
	for i, e := range cfg.TrustedIssuerOrigins {
		if why := allowlist.Check(e, trustHints); why != "" {
			return nil, fmt.Errorf("%w: issuermeta: Config.TrustedIssuerOrigins[%d] %s", jose.ErrInvalidArgument, i, why)
		}
	}
	redirects, err := cfg.Redirects.rule()
	if err != nil {
		return nil, err
	}
	l := limits
	l.Follow = redirects.Follows
	r := &Resolver{
		trusted: allowlist.New(cfg.TrustedIssuerOrigins),
		limits:  l,
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

// trustHints complete the texts of a refused entry of TrustedIssuerOrigins.
var trustHints = allowlist.Hints{
	All:   "leave Config.TrustedIssuerOrigins empty",
	Finer: "list the origin and refuse the other iss in a Resolver that wraps this one",
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
//     iss is not a URI (§4, RFC 3986), or not an https URL with a
//     host and no query or fragment (§2.5, §4) and no userinfo (RFC 9110
//     §4.2.4), or its path has a dot-segment (draft 20 §4) or a form a server
//     may resolve as one, or TrustedIssuerOrigins does not cover its origin;
//   - an error wrapping issuerkey.ErrNoUsableKey: the issuer's server
//     answered, and the metadata or the JWK Set is not valid (§4.2, §4.3,
//     RFC 7517 §4, §5), so it must not be used;
//   - any other error: a retrieval failed (§3). It wraps the cause: a
//     StatusError, ErrRedirectNotAllowed, ErrRedirectTargetNotAllowed,
//     ErrTooManyRedirects, ErrContentTypeNotAccepted, ErrBodyTooLarge,
//     ErrAddressBlocked, whose text names the blocked address, or an error
//     of the client, such as context.Canceled. Printing a cause on its own
//     prints its text, which for an error of net/http may hold the URL or a
//     redirect target.
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
	if !r.trusted.Covers(u) {
		return nil, fmt.Errorf("%w: issuermeta: the origin of iss is not covered by Config.TrustedIssuerOrigins; list it there to trust it", issuerkey.ErrIssuerNotSupported)
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
// issuerkey.ErrIssuerNotSupported: iss is not a URI (RFC 3986), or not an
// https URL with a host and no userinfo, query or fragment, or its path has a
// dot-segment (draft-ietf-oauth-sd-jwt-vc-20 §4) or a form a server may resolve
// as one.
func MetadataURL(iss string) (string, error) {
	_, s, err := metadataURL(iss)
	return s, err
}

func metadataURL(iss string) (*url.URL, string, error) {
	// A DID is a valid iss for another resolver, so the text says which one
	// to supply rather than call the iss wrong.
	if strings.HasPrefix(iss, "did:") {
		return nil, "", fmt.Errorf("%w: issuermeta: iss is a DID; use didresolver for a DID iss", issuerkey.ErrIssuerNotSupported)
	}
	// draft-ietf-oauth-sd-jwt-vc-19 §4: iss MUST be an https URL as defined
	// in RFC 3986; url.Parse accepts more, such as a host in Unicode.
	if !uri.Valid(iss) {
		return nil, "", fmt.Errorf("%w: issuermeta: iss is not a URI (RFC 3986)", issuerkey.ErrIssuerNotSupported)
	}
	u, err := url.Parse(iss)
	if err != nil || !safehttp.HTTPSURL(u) {
		return nil, "", fmt.Errorf("%w: issuermeta: iss is not an https URL with a host (draft-ietf-oauth-sd-jwt-vc-19 §4) and no userinfo (RFC 9110 §4.2.4)", issuerkey.ErrIssuerNotSupported)
	}
	// RFC 3986 §3: neither character appears raw in the authority or path,
	// so either one starts a query or fragment, even an empty one.
	if strings.ContainsAny(iss, "?#") {
		return nil, "", fmt.Errorf("%w: issuermeta: iss has a query or fragment, which draft-ietf-oauth-sd-jwt-vc-19 §4 forbids", issuerkey.ErrIssuerNotSupported)
	}
	if hasDotSegment(u.Path) {
		return nil, "", fmt.Errorf("%w: issuermeta: the path of iss has a dot-segment (draft-ietf-oauth-sd-jwt-vc-20 §4) or a form a server may resolve as one, which this SDK refuses; the issuer must name itself without one", issuerkey.ErrIssuerNotSupported)
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

// hasDotSegment reports whether path, decoded once by url.Parse, has a "." or
// ".." segment. A server that resolves one answers from outside /.well-known/,
// the path RFC 8615 §4.1 asks operators to guard, so whoever can publish a file
// on the origin could serve metadata for an iss there.
//
// Beyond the pin: draft 19 §4 allows dot-segments in iss.
// draft-ietf-oauth-sd-jwt-vc-20 §4, unchanged to -23, forbids them to the
// Issuer, and the Resolver refuses them as recipient policy (draft 19 §2.5).
// RFC 3986 §2.3 makes %2e the same. Decoded %2F and %5C separators and ";"
// parameters are SDK policy, for servers that resolve those too (nginx a
// decoded %2F, Jetty in UNSAFE mode ";"); no issuer needs them.
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
	body, fresh, err := httpcache.Get(ctx, r.client, metaURL, []string{mediaTypeMetadata}, r.limits, maxCacheLifetime)
	if err != nil {
		return nil, time.Time{}, retrievalErr("the issuer metadata", err)
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
	jwksURI, hasURI := meta["jwks_uri"]
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
		s, ok := jwksURI.(string)
		// §4.2: jwks_uri is a URL string, so a URI (RFC 3986 §1.1.3), which
		// url.Parse does not check.
		if ok && !uri.Valid(s) {
			return nil, time.Time{}, contentFault("jwks_uri is not a URI (RFC 3986)")
		}
		if u, err := url.Parse(s); err != nil || !safehttp.HTTPSURL(u) {
			return nil, time.Time{}, contentFault("jwks_uri is not an https URL with a host (draft-ietf-oauth-sd-jwt-vc-19 §3, §4.2) and no userinfo (RFC 9110 §4.2.4)")
		}
		sent := r.now()
		body, fresh, err := httpcache.Get(ctx, r.client, s, mediaTypesJWKSet, r.limits, maxCacheLifetime)
		if err != nil {
			return nil, time.Time{}, retrievalErr("the JWK Set", err)
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

// retrievalErr is the error of a failed retrieval of what; a refused
// redirect also says how the issuer or the verifier can fix it.
func retrievalErr(what string, err error) error {
	if errors.Is(err, safehttp.ErrNotFollowed) {
		return fmt.Errorf("issuermeta: fetching %s: %w: the redirect leaves the origin of the URL requested for a target Config.Redirects does not allow; the issuer must serve it from that origin, or the verifier allows the target with RedirectTo", what, err)
	}
	return fmt.Errorf("issuermeta: fetching %s: %w", what, err)
}

// contentFault is the error of a metadata document or JWK Set that must not
// be used: it wraps issuerkey.ErrNoUsableKey, and the arguments, such as a
// jose.ErrMalformed, with %w.
func contentFault(format string, a ...any) error {
	return fmt.Errorf("%w: issuermeta: "+format, append([]any{issuerkey.ErrNoUsableKey}, a...)...)
}
