// Checking the status of a Referenced Token against its Status List Token in
// JWT format: draft-ietf-oauth-status-list-21 §8 (§8.1 request, §8.2
// response, §8.3 validation) and §5.1.

package statuslist

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/pilacorp/go-credential-sdk/digitalcredential/internal/safehttp"
	"github.com/pilacorp/go-credential-sdk/digitalcredential/issuerkey"
	"github.com/pilacorp/go-credential-sdk/jose"
	"github.com/pilacorp/go-credential-sdk/jose/jws"
	"github.com/pilacorp/go-credential-sdk/jose/jwt"
)

// Fixed limits of the Checker; every value is SDK policy. Draft 21 leaves
// freshness and caching to the Relying Party (§8.3 step 4b, §13.7), asks for
// bounds on ttl without a number (§11.5), and leaves restrictions on the uri
// to it (§6.2); the fetch applies draft-ietf-oauth-sd-jwt-vc-19 §3.
const (
	mediaTypeJWT     = "application/" + typStatusList // §8.1, §8.2; RFC 7515 §4.1.9
	fetchTimeout     = 5 * time.Second                // sd-jwt-vc-19 §3: time-bound
	maxRedirects     = 3                              // sd-jwt-vc-19 §3: MUST limit redirects
	clockSkew        = time.Minute                    // RFC 7519 §4.1.4, §4.1.5: small leeway
	maxCacheLifetime = 24 * time.Hour                 // upper bound on ttl (§11.5)
	maxCacheBytes    = 32 << 20                       // list capacity plus key lengths
	// decodeSlots bounds concurrent Decode calls: an lst of a few KiB can
	// inflate to 16 MiB, and each Decode allocates several times that.
	decodeSlots = 4
)

// Ref is the status_list member of a Referenced Token's status claim (draft
// 21 §6.2).
type Ref struct {
	// URI is uri, the URI of the Status List Token, equal to its sub (§5.1);
	// it must be a URI conforming to RFC 3986 (§6.2), with a host when it
	// is http or https (RFC 9110 §4.2.1, §4.2.2).
	URI string
	// Index is idx, the entry of the Referenced Token; it must not be
	// negative.
	Index int
}

// Validate checks r against draft 21 §6.2, wrapping jose.ErrInvalidArgument:
// uri is a URI (RFC 3986), with a host when it is http or https (RFC 9110
// §4.2.1, §4.2.2), and idx is not negative. An issuer writing r into
// a Referenced Token checks it here; Checker.Status applies it too, and then
// its own https rule.
func (r Ref) Validate() error {
	if err := checkListURI(r.URI); err != nil {
		return fmt.Errorf("%w: statuslist: Ref.URI %v", jose.ErrInvalidArgument, err)
	}
	// §6.2: idx is a non-negative integer.
	if r.Index < 0 {
		return fmt.Errorf("%w: statuslist: Ref.Index %d is negative", jose.ErrInvalidArgument, r.Index)
	}
	return nil
}

// Checker reads the status of Referenced Tokens from their Status List
// Tokens in JWT format. Construct it with NewChecker and share one instance:
// the decode bound, the cache and the default client's connections belong to
// the instance. It is safe for concurrent use.
//
// Its limits are fixed: the fetch of a token ends within 5 seconds, follows at
// most 3 redirects and reads at most 1 MiB, the cap SignToken signs to; a list
// inflates to at most 16 MiB; the clock skew is 1 minute. It caches verified
// lists for the token's ttl, at most 24 hours and never past exp; a token
// without ttl is not cached. The cache counts 32 MiB of list bytes (their
// capacity) plus key lengths, not total heap. When live entries fill it, a new
// list is not cached until one expires; no live entry is evicted.
//
// At most 4 lists are decoded at once, in arrival order. Each cache miss holds
// up to about 1 MiB of token data until its decode runs, and the issuer's
// token sets how long each decode takes, so one issuer's lists can delay
// other issuers' cache misses; cache hits are not delayed. Bound waiting with
// ctx deadlines, and bound your own concurrency.
//
// The default client refuses addresses that are not globally reachable, but
// hosts reachable only inside the deployment's own network are known to no
// registry: the deployment's egress policy must block them
// (draft-ietf-oauth-sd-jwt-vc-19 §7.1).
type Checker struct {
	issuers issuerkey.Resolver
	client  *http.Client
	now     func() time.Time
	slots   chan struct{}

	mu    sync.Mutex
	cache map[cacheKey]cacheEntry
	used  int // bytes of the cached entries
}

// Option configures a Checker.
type Option func(*Checker)

// WithHTTPClient makes the Checker fetch Status List Tokens with c instead of
// its default client; nil keeps the default. A deployment behind an egress
// proxy, or with status lists on an internal host, passes its own client.
//
// c is trusted code. The URL checks and the limits of the Checker still judge
// the URLs requested and the response returned, but the address check exists
// only in the default transport, and the 5-second timeout holds only if the
// transport of c honours the request context.
func WithHTTPClient(c *http.Client) Option {
	return func(ch *Checker) {
		if c != nil {
			ch.client = c
		}
	}
}

// NewChecker returns a Checker that verifies Status List Tokens with the keys
// issuers returns. issuers must be the resolver the Referenced Token itself is
// verified with, which the Checker cannot check: the SDK accepts a list only
// under a key of the credential's issuer, the same-key or same-resolution
// options of draft 21 §11.3. A separate Status Issuer linked by X.509 PKI
// (§11.3, §13.5) is not supported. A nil issuers is jose.ErrInvalidArgument;
// nil options are skipped.
func NewChecker(issuers issuerkey.Resolver, opts ...Option) (*Checker, error) {
	if issuers == nil {
		return nil, fmt.Errorf("%w: statuslist: nil issuer key resolver", jose.ErrInvalidArgument)
	}
	c := &Checker{
		issuers: issuers,
		now:     time.Now,
		slots:   make(chan struct{}, decodeSlots),
		cache:   map[cacheKey]cacheEntry{},
	}
	for _, opt := range opts {
		if opt != nil {
			opt(c)
		}
	}
	if c.client == nil {
		c.client = safehttp.NewClient()
	}
	return c, nil
}

// Status returns the status value of entry ref.Index in the Status List
// Token at ref.URI, which must be signed by a key of the issuer iss (see
// NewChecker). The value is returned raw, including application-specific ones (§7.1); what it
// means for the token is the caller's decision (§8.3 step 7). The caller
// validates the Referenced Token first (§8.3: its processing rules precede
// any status evaluation).
//
// A Checker not made by NewChecker, a nil ctx, a ref breaking the rules of
// Ref, or a ref.URI that is not an https URL with a host and no userinfo are
// jose.ErrInvalidArgument; so is an index outside the list, which
// makes the Referenced Token invalid (§8.3 step 6) rather than being a caller
// mistake. Any error means no statement about the status can be made (§8.3),
// and is never a status: a failed fetch, a token that is malformed, not
// signed by a key of iss (issuerkey.Select), carrying an iss claim other
// than iss (RFC 8725 §3.8), or failing a check of §5.1 or §8.3, an lst
// Decode refuses, or an index outside the list. Errors of the fetch, the
// resolver, jose/jws and jose/jwt are wrapped unchanged, so context.Canceled
// stays visible.
func (c *Checker) Status(ctx context.Context, ref Ref, iss string) (uint8, error) {
	if c == nil || c.issuers == nil {
		return 0, fmt.Errorf("%w: statuslist: Checker not made by NewChecker", jose.ErrInvalidArgument)
	}
	if ctx == nil {
		return 0, fmt.Errorf("%w: statuslist: nil context", jose.ErrInvalidArgument)
	}
	if err := ref.Validate(); err != nil {
		return 0, err
	}
	// The SDK's verifier default: §6.2 leaves restrictions on uri to the
	// Relying Party.
	if u, err := url.Parse(ref.URI); err != nil || !safehttp.HTTPSURL(u) {
		return 0, fmt.Errorf("%w: statuslist: Ref.URI is not an https URL with a host and no userinfo", jose.ErrInvalidArgument)
	}
	// Keyed by iss too: keyed by uri alone, a list verified with one issuer's
	// key would answer for another issuer's token pointing to the same uri.
	key := cacheKey{iss: iss, uri: ref.URI}
	l := c.cached(key)
	if l == nil {
		var err error
		if l, err = c.load(ctx, key); err != nil {
			return 0, err
		}
	}
	return l.Get(ref.Index)
}

// load fetches, verifies and decodes the Status List Token of key and caches
// the list before any index is read, so an index outside it is answered from
// the cache too.
func (c *Checker) load(ctx context.Context, key cacheKey) (*List, error) {
	fetched := c.now()
	// §8.1, §8.2; redirects bounded (§11.4) to maxRedirects.
	body, _, err := safehttp.Get(ctx, c.client, key.uri, mediaTypeJWT,
		safehttp.Limits{Timeout: fetchTimeout, MaxRedirects: maxRedirects, MaxBytes: maxTokenBytes})
	if err != nil {
		return nil, fmt.Errorf("statuslist: %w", err)
	}
	// §8.2: the body is the token in JWS Compact Serialization, nothing more;
	// jws refuses whitespace around it (RFC 7515 §7.1).
	token := string(body)
	header, err := jws.UnverifiedHeader(token)
	if err != nil {
		return nil, fmt.Errorf("statuslist: token: %w", err)
	}
	// §5.1: typ MUST be statuslist+jwt (RFC 8725 §3.11). Refusing on the
	// unverified header accepts nothing and spares the resolver call.
	if !header.TypIs(typStatusList) {
		return nil, errors.New("statuslist: token typ is not statuslist+jwt")
	}
	keys, err := c.issuers.Keys(ctx, key.iss)
	if err != nil {
		return nil, fmt.Errorf("statuslist: issuer keys: %w", err)
	}
	pub, err := issuerkey.Select(keys, header)
	if err != nil {
		return nil, fmt.Errorf("statuslist: %w", err)
	}
	// §5.1 rule 2 and §8.3 step 3a: the signature is checked before any
	// claim is read.
	_, payload, err := jws.Verify(token, pub, nil)
	if err != nil {
		return nil, fmt.Errorf("statuslist: token: %w", err)
	}
	claims, err := jose.DecodeJSONObject(payload)
	if err != nil {
		return nil, fmt.Errorf("statuslist: token claims: %w", err)
	}
	tc, err := checkClaims(claims, key.iss, key.uri, c.now())
	if err != nil {
		return nil, err
	}

	// Decode is the costly step; the slot bounds how many run at once. A
	// caller that waited may find the list cached by another meanwhile.
	select {
	case c.slots <- struct{}{}:
	case <-ctx.Done():
		return nil, fmt.Errorf("statuslist: %w", ctx.Err())
	}
	if l := c.cached(key); l != nil {
		<-c.slots
		return l, nil
	}
	l, err := Decode(tc.lst, tc.bits) // §8.3 step 5
	<-c.slots
	if err != nil {
		return nil, err
	}
	// The wait for a slot may have taken the token past exp: the same rule
	// again, so an expired list is never answered.
	if err := jwt.CheckExpNbf(claims, c.now(), clockSkew); err != nil {
		return nil, fmt.Errorf("statuslist: token: %w", err)
	}

	// §8.3 step 4d and §13.7: cached for ttl from the fetch, at most 24
	// hours (§11.5) and never past exp. No ttl, no cache: stricter than §13.7,
	// which allows caching until exp, because without ttl the issuer states
	// no refresh interval, and caching until exp or for 24 hours would hide
	// revocations that long; checking more often is always allowed.
	if tc.ttl > 0 {
		expires := fetched.Add(tc.ttl)
		if tc.hasExp && tc.exp.Before(expires) {
			expires = tc.exp
		}
		c.store(key, l, tc.iat, expires)
	}
	return l, nil
}

// listClaims are the claims of a verified Status List Token the Checker uses.
type listClaims struct {
	lst    string
	bits   int
	iat    time.Time
	ttl    time.Duration // 0: not cached
	exp    time.Time
	hasExp bool
}

// checkClaims applies §5.1 and §8.3 step 4 to the claims of a verified token
// fetched from uri and verified with a key of iss.
func checkClaims(claims map[string]any, iss, uri string, now time.Time) (listClaims, error) {
	var tc listClaims
	// §5.1 and §8.3 step 4a: sub equals the uri of the Referenced Token,
	// compared without transformation (RFC 7519 §7.3).
	if sub, _ := claims["sub"].(string); sub != uri {
		return tc, errors.New("statuslist: token sub is not the uri of the Referenced Token")
	}
	// RFC 8725 §3.8: a present iss must own the key that verified the token.
	// The Checker verifies only with keys of iss (see NewChecker), so iss, a
	// string (RFC 7519 §4.1.1), must equal it unchanged (RFC 7519 §7.3).
	if v, ok := claims["iss"]; ok {
		if s, isString := v.(string); !isString || s != iss {
			return tc, errors.New("statuslist: token iss is not the issuer of the Referenced Token")
		}
	}
	// §5.1: iat is REQUIRED (§8.3 step 3b). One later than now + skew is
	// refused, a freshness policy §8.3 step 4b leaves to the Relying Party.
	iat, ok, err := jwt.DateClaim(claims, "iat")
	if err != nil {
		return tc, fmt.Errorf("statuslist: token: %w", err)
	}
	if !ok {
		return tc, errors.New("statuslist: token has no iat")
	}
	if iat.After(now.Add(clockSkew)) {
		return tc, errors.New("statuslist: token iat is in the future")
	}
	tc.iat = iat
	// §5.1 rule 3 and §8.3 step 4c: exp, and nbf, per RFC 7519 §4.1.4, §4.1.5.
	if err := jwt.CheckExpNbf(claims, now, clockSkew); err != nil {
		return tc, fmt.Errorf("statuslist: token: %w", err)
	}
	if tc.exp, tc.hasExp, err = jwt.DateClaim(claims, "exp"); err != nil {
		return tc, fmt.Errorf("statuslist: token: %w", err)
	}
	// RFC 7519 §4.1.3: a JWT with aud MUST be rejected by a principal that
	// does not identify itself with a value in it, and the Checker has no
	// identity to match.
	if _, ok := claims["aud"]; ok {
		return tc, errors.New("statuslist: token has aud")
	}
	// §5.1: ttl, when present, is a positive number of seconds, a fraction
	// allowed; values over 24 hours, the SDK's bound (§11.5 gives no
	// number), are cut there.
	if v, ok := claims["ttl"]; ok {
		n, _ := v.(json.Number) // any other type reads as "" and fails to parse
		f, err := strconv.ParseFloat(string(n), 64)
		if err != nil || !(f > 0) {
			return tc, errors.New("statuslist: token ttl is not a positive number")
		}
		tc.ttl = maxCacheLifetime
		if f < maxCacheLifetime.Seconds() {
			tc.ttl = time.Duration(f * float64(time.Second))
		}
	}
	// §5.1 and §4.2: status_list holds bits, a JSON integer (Decode checks
	// its value), and lst, a string.
	sl, ok := claims["status_list"].(map[string]any)
	if !ok {
		return tc, fmt.Errorf("%w: statuslist: token status_list is not an object", jose.ErrMalformed)
	}
	n, _ := sl["bits"].(json.Number)
	if tc.bits, err = strconv.Atoi(string(n)); err != nil {
		return tc, fmt.Errorf("%w: statuslist: token status_list bits is not an integer", jose.ErrMalformed)
	}
	if tc.lst, ok = sl["lst"].(string); !ok {
		return tc, fmt.Errorf("%w: statuslist: token status_list lst is not a string", jose.ErrMalformed)
	}
	return tc, nil
}
