// The order of the checks follows eudi-lib-kmp-statium (commit
// 118171ff25c4dcd8f74e6f30ceb58f245ec3ea4e, Apache-2.0):
// GetStatusListToken.kt (fetch, signature, typ), StatusListTokenValidations.kt
// (ensureSubject, ensureIssuedBefore, ensureNotExpired) and GetStatus.kt (read
// the index), rewritten in Go. Fetch and inflate limits, the SSRF-checking
// dialer and the ttl cache are additions.

package statuslist

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/pilacorp/go-credential-sdk/digitalcredential/internal/safehttp"
	"github.com/pilacorp/go-credential-sdk/jose"
)

// IssuerKeyResolver returns the public key of the issuer iss for a token with
// header h (h.Kid() selects the key inside the issuer's key set).
//
// It has the method set of digitalcredential.IssuerKeyResolver (spec S3), with
// the header typed jose.Header. It is declared here because the root package
// imports statuslist and statuslist must not import the root package. Go
// interfaces are satisfied by method set, so every resolver written for
// Verify (issuermeta, or a caller's own) is also an IssuerKeyResolver here:
// the Checker is meant to get the same resolver as the credential.
type IssuerKeyResolver interface {
	IssuerKey(ctx context.Context, iss string, h jose.Header) (*ecdsa.PublicKey, error)
}

// Ref points to one entry of a status list: status.status_list {uri, idx} of a
// credential. The root package is meant to declare
// `type StatusRef = statuslist.Ref`.
type Ref struct {
	URI   string // https URL of the status list token
	Index int    // idx, ≥ 0
}

// Result is the status read for a credential. Value is the raw entry,
// application-specific values included; Verify decides whether it is accepted
// (Policy.AcceptedStatus).
type Result struct {
	Value byte
}

// Defaults of Options.
const (
	DefaultClockSkew     = time.Minute
	DefaultMaxCacheBytes = 32 << 20
	// MaxCacheTTL caps how long a token is cached, whatever its ttl says.
	MaxCacheTTL = 24 * time.Hour
)

// Options configures NewChecker. Zero values take the defaults.
type Options struct {
	// Issuers resolves the key the token must be signed with, from the
	// credential's iss and the token's kid. Required; pass the resolver used
	// for the credential, so a list counts only if the credential's issuer
	// signed it.
	Issuers IssuerKeyResolver
	// AllowedAlgs of the token signature; default {"ES256", "ES256K"}.
	AllowedAlgs []string
	// ClockSkew allowed on iat and exp, never negative. 0 means the default
	// of 1 minute, so zero tolerance cannot be expressed.
	ClockSkew time.Duration
	// Now returns the current time; default time.Now.
	Now func() time.Time

	// Timeout of one fetch; default 5 s.
	Timeout time.Duration
	// MaxRedirects followed, each to https; default 3, negative for none.
	// Applies to the default client only.
	MaxRedirects int
	// MaxBytes of the token body; default 64 KB. A larger body is an error,
	// never truncated.
	MaxBytes int64
	// MaxListBytes the lst may inflate to; default DefaultMaxListBytes (16 MB).
	MaxListBytes int64
	// MaxCacheBytes bounds the total size of cached lists; default 32 MB,
	// negative disables the cache.
	MaxCacheBytes int64

	// HTTPClient replaces the default client. The default refuses internal
	// addresses at the dialer, follows only HTTPS redirects and ignores proxy
	// environment variables; a client given here is used as is, so that
	// protection is then the caller's job. The https-only URL, status,
	// Content-Type and size checks apply to every client.
	HTTPClient *http.Client
	// AllowPrivateNetworks lets the default client connect to internal
	// addresses. Tests and local development only.
	AllowPrivateNetworks bool
}

// Checker reads the status of a credential from its status list token
// (draft 21 §8.3, token only: reading the list back from the chain is a later
// step). Safe for concurrent use.
type Checker struct {
	issuers      IssuerKeyResolver
	allowedAlgs  []string
	skew         time.Duration
	now          func() time.Time
	timeout      time.Duration
	maxBytes     int64
	maxListBytes int64
	client       *http.Client
	cache        *listCache // nil: no cache
}

// NewChecker validates o and applies the defaults.
func NewChecker(o Options) (*Checker, error) {
	if o.Issuers == nil {
		return nil, fmt.Errorf("%w: Options.Issuers is required", ErrInvalidArgument)
	}
	algs := slices.Clone(o.AllowedAlgs)
	if len(algs) == 0 {
		algs = []string{jose.AlgES256, jose.AlgES256K}
	}
	for _, a := range algs {
		if a != jose.AlgES256 && a != jose.AlgES256K {
			return nil, fmt.Errorf("%w: alg %q, want ES256 or ES256K", ErrInvalidArgument, a)
		}
	}
	if o.ClockSkew < 0 {
		return nil, fmt.Errorf("%w: negative ClockSkew", ErrInvalidArgument)
	}
	c := &Checker{
		issuers:      o.Issuers,
		allowedAlgs:  algs,
		skew:         o.ClockSkew,
		now:          o.Now,
		timeout:      o.Timeout,
		maxBytes:     o.MaxBytes,
		maxListBytes: o.MaxListBytes,
		client:       o.HTTPClient,
	}
	if c.skew == 0 {
		c.skew = DefaultClockSkew
	}
	if c.now == nil {
		c.now = time.Now
	}
	if c.timeout <= 0 {
		c.timeout = safehttp.DefaultTimeout
	}
	if c.maxBytes <= 0 {
		c.maxBytes = safehttp.DefaultMaxBytes
	}
	if c.maxListBytes <= 0 {
		c.maxListBytes = DefaultMaxListBytes
	}
	if c.client == nil {
		c.client = safehttp.NewClient(safehttp.Options{
			Timeout:              c.timeout,
			MaxRedirects:         o.MaxRedirects,
			AllowPrivateNetworks: o.AllowPrivateNetworks,
		})
	}
	switch {
	case o.MaxCacheBytes == 0:
		c.cache = newListCache(DefaultMaxCacheBytes)
	case o.MaxCacheBytes > 0:
		c.cache = newListCache(o.MaxCacheBytes)
	}
	return c, nil
}

// Status returns the entry ref.Index of the list at ref.URI, for a credential
// issued by iss. vct is accepted for the status profiles and the on-chain
// reading of later steps; the token-only Checker does not use it.
//
// Steps, in statium's order:
//  1. a cached list for (iss, ref.URI) that has not expired → step 9;
//  2. GET ref.URI with Accept: application/statuslist+jwt, through the
//     SSRF-checking client, within Timeout, MaxRedirects and MaxBytes; status
//     200 and Content-Type application/statuslist+jwt;
//  3. signature first: the key comes from Issuers with the credential's iss
//     and the token's header, so the list must be signed by the credential's
//     issuer; then jose.Verify with AllowedAlgs;
//  4. typ is statuslist+jwt;
//  5. sub equals ref.URI character for character;
//  6. iat present and ≤ now + skew; exp, if present, ≥ now − skew;
//  7. status_list.lst decoded with status_list.bits (1, 2, 4 or 8) within
//     MaxListBytes;
//  8. cached until min(now + ttl, now + 24 h, exp); no ttl, no cache;
//  9. entry ref.Index read (ErrIndexOutOfRange outside).
//
// Any failure is returned as an error, never as a status value; nothing that
// failed steps 2 to 7 is cached.
func (c *Checker) Status(ctx context.Context, ref Ref, iss, vct string) (*Result, error) {
	if err := checkHTTPSURI(ref.URI); err != nil {
		return nil, fmt.Errorf("%w: uri: %v", ErrInvalidArgument, err)
	}
	if ref.Index < 0 {
		return nil, fmt.Errorf("%w: %d", ErrIndexOutOfRange, ref.Index)
	}
	if iss == "" {
		return nil, fmt.Errorf("%w: iss is required", ErrInvalidArgument)
	}
	key := cacheKey(iss, ref.URI)
	if c.cache != nil {
		if l, ok := c.cache.get(key, c.now()); ok {
			return read(l, ref.Index)
		}
	}

	fetchCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	body, _, err := safehttp.Get(fetchCtx, c.client, ref.URI, MediaType, c.maxBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFetch, err)
	}
	now := c.now()
	l, expires, err := c.verifyToken(ctx, strings.TrimSpace(string(body)), ref.URI, iss, now)
	if err != nil {
		return nil, err
	}
	// The list is verified: cache it before reading the index, so an index
	// past its end is answered from the cache next time instead of fetching
	// the list again.
	if c.cache != nil && expires.After(now) {
		c.cache.put(key, l, expires)
	}
	return read(l, ref.Index)
}

func read(l *List, i int) (*Result, error) {
	v, err := l.Get(i)
	if err != nil {
		return nil, err
	}
	return &Result{Value: v}, nil
}

// cacheKey keys the cache by issuer and uri: a list verified with issuer A's
// key must never answer for a credential of issuer B that points to the same
// uri. The length prefix keeps the pair unambiguous.
func cacheKey(iss, uri string) string {
	return strconv.Itoa(len(iss)) + ":" + iss + uri
}

// verifyToken runs steps 3 to 7 and returns the list and the time its cache
// entry expires (step 8; zero: do not cache).
func (c *Checker) verifyToken(ctx context.Context, token, uri, iss string, now time.Time) (*List, time.Time, error) {
	var none time.Time
	header, err := unverifiedHeader(token)
	if err != nil {
		return nil, none, err
	}
	pub, err := c.issuers.IssuerKey(ctx, iss, header)
	if err != nil {
		return nil, none, fmt.Errorf("%w: %w", ErrIssuerKey, err)
	}
	if pub == nil {
		return nil, none, fmt.Errorf("%w: resolver returned no key", ErrIssuerKey)
	}
	h, payload, err := jose.Verify(token, pub, c.allowedAlgs)
	if err != nil {
		return nil, none, fmt.Errorf("%w: signature: %w", ErrTokenInvalid, err)
	}
	if typ := h.Typ(); typ != TokenType {
		return nil, none, fmt.Errorf("%w: typ %q, want %s", ErrTokenInvalid, typ, TokenType)
	}
	claims, err := jose.DecodeJSONObject(payload)
	if err != nil {
		return nil, none, fmt.Errorf("%w: payload: %w", ErrMalformed, err)
	}
	if sub, _ := claims["sub"].(string); sub != uri {
		return nil, none, fmt.Errorf("%w: sub %q differs from uri %q", ErrTokenInvalid, sub, uri)
	}
	iat, ok := numericDate(claims["iat"])
	if !ok {
		return nil, none, fmt.Errorf("%w: iat is missing or not a NumericDate", ErrTokenInvalid)
	}
	if iat.After(now.Add(c.skew)) {
		return nil, none, fmt.Errorf("%w: issued after the validation time", ErrTokenInvalid)
	}
	var exp time.Time
	if v, present := claims["exp"]; present {
		if exp, ok = numericDate(v); !ok {
			return nil, none, fmt.Errorf("%w: exp is not a NumericDate", ErrTokenInvalid)
		}
		if exp.Before(now.Add(-c.skew)) {
			return nil, none, fmt.Errorf("%w: expired", ErrTokenInvalid)
		}
	}
	sl, ok := claims["status_list"].(map[string]any)
	if !ok {
		return nil, none, fmt.Errorf("%w: status_list is missing or not an object", ErrMalformed)
	}
	bits, err := intClaim(sl["bits"])
	if err != nil {
		return nil, none, fmt.Errorf("%w: status_list.bits: %v", ErrMalformed, err)
	}
	lst, ok := sl["lst"].(string)
	if !ok {
		return nil, none, fmt.Errorf("%w: status_list.lst is missing or not a string", ErrMalformed)
	}
	l, err := decode(lst, bits, c.maxListBytes)
	if err != nil {
		return nil, none, err
	}

	var expires time.Time
	if v, present := claims["ttl"]; present {
		ttl, ok := positiveSeconds(v)
		if !ok {
			return nil, none, fmt.Errorf("%w: ttl is not a positive number", ErrMalformed)
		}
		expires = now.Add(ttl)
		if !exp.IsZero() && exp.Before(expires) {
			expires = exp
		}
	}
	return l, expires, nil
}

// unverifiedHeader reads the header before the signature is checked, only to
// hand it to the resolver (which picks the key by kid). Nothing in it is
// trusted until jose.Verify has passed.
func unverifiedHeader(token string) (jose.Header, error) {
	first, _, ok := strings.Cut(token, ".")
	if !ok {
		return nil, fmt.Errorf("%w: not a compact JWS", ErrMalformed)
	}
	raw, err := jose.DecodeSegment(first)
	if err != nil {
		return nil, fmt.Errorf("%w: header: %w", ErrMalformed, err)
	}
	obj, err := jose.DecodeJSONObject(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: header: %w", ErrMalformed, err)
	}
	return jose.Header(obj), nil
}

// numericDate reads a JWT NumericDate (RFC 7519 §2): a JSON number of seconds,
// integer or not.
func numericDate(v any) (time.Time, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return time.Time{}, false
	}
	if i, err := n.Int64(); err == nil {
		return time.Unix(i, 0), true
	}
	f, err := n.Float64()
	if err != nil || math.IsNaN(f) || math.Abs(f) > 1<<53 {
		return time.Time{}, false
	}
	sec, frac := math.Modf(f)
	return time.Unix(int64(sec), int64(frac*1e9)), true
}

// positiveSeconds reads ttl: a positive JSON number of seconds, capped at
// MaxCacheTTL.
func positiveSeconds(v any) (time.Duration, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	f, err := n.Float64()
	if err != nil || math.IsNaN(f) || f <= 0 {
		return 0, false
	}
	if f >= MaxCacheTTL.Seconds() {
		return MaxCacheTTL, true
	}
	return time.Duration(f * float64(time.Second)), true
}

func intClaim(v any) (int, error) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, fmt.Errorf("not a number")
	}
	i, err := n.Int64()
	if err != nil || i < math.MinInt32 || i > math.MaxInt32 {
		return 0, fmt.Errorf("%s is not an integer", n)
	}
	return int(i), nil
}
