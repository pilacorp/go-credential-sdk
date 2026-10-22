package statuslist

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pilacorp/go-credential-sdk/digitalcredential/internal/safehttp"
	"github.com/pilacorp/go-credential-sdk/jose"
)

const (
	issA = "https://issuer-a.example/issuers/did:nda:testnet:0xaaa"
	issB = "https://issuer-b.example/issuers/did:nda:testnet:0xbbb"
	kidA = "did:nda:testnet:0xaaa#key-2"
)

// env is one issuer (A, P-256) serving its list from one TLS server, a second
// issuer (B) known to the resolver, and a clock the test moves.
type env struct {
	srv      *server
	signer   jose.Signer
	signerB  jose.Signer
	resolver *resolver
	now      time.Time
	checker  *Checker
}

func newEnv(t *testing.T, o Options) *env {
	t.Helper()
	signer, pub := newP256(t)
	signerB, pubB := newP256(t)
	e := &env{
		srv:      newServer(t),
		signer:   signer,
		signerB:  signerB,
		resolver: &resolver{keys: map[string]*ecdsa.PublicKey{issA: pub, issB: pubB}},
		now:      t0,
	}
	o.Issuers = e.resolver
	o.Now = func() time.Time { return e.now }
	if o.HTTPClient == nil {
		o.HTTPClient = testClient(t, e.srv.Server)
	}
	c, err := NewChecker(o)
	if err != nil {
		t.Fatal(err)
	}
	e.checker = c
	return e
}

// serve signs l with issuer A's key and the given claims and serves it.
func (e *env) serve(t *testing.T, l *List, c TokenClaims) {
	t.Helper()
	if c.Sub == "" {
		c.Sub = e.srv.uri()
	}
	if c.IssuedAt.IsZero() {
		c.IssuedAt = e.now
	}
	tok, err := SignToken(l, c, SigningKey{Signer: e.signer, KID: kidA})
	if err != nil {
		t.Fatal(err)
	}
	e.srv.set(tok)
}

// serveRaw signs an arbitrary header and payload with issuer A's key.
func (e *env) serveRaw(t *testing.T, header map[string]any, payload string) {
	t.Helper()
	e.srv.set(signRaw(t, e.signer, jose.AlgES256, header, payload))
}

func (e *env) status(index int) (*Result, error) {
	return e.checker.Status(context.Background(), Ref{URI: e.srv.uri(), Index: index}, issA, "urn:vct:test")
}

func TestCheckerReadsEveryWidth(t *testing.T) {
	for _, tc := range []struct {
		bits  int
		value byte
	}{{1, 0x01}, {2, 0x02}, {2, 0x03}, {4, 0x0C}, {4, 0x0F}, {8, 0xA5}} {
		t.Run(fmt.Sprintf("bits %d value %#x", tc.bits, tc.value), func(t *testing.T) {
			e := newEnv(t, Options{})
			e.serve(t, mustList(t, 2000, tc.bits, map[int]byte{917: tc.value}), TokenClaims{})
			res, err := e.status(917)
			if err != nil || res.Value != tc.value {
				t.Fatalf("Status(917) = %v, %v; want %#x", res, err, tc.value)
			}
			if res, err := e.status(916); err != nil || res.Value != 0 {
				t.Fatalf("Status(916) = %v, %v; want 0", res, err)
			}
		})
	}
}

func TestCheckerES256KToken(t *testing.T) {
	e := newEnv(t, Options{})
	signer, pub := newSecpVault(t)
	e.resolver.keys[issA] = pub
	tok, err := SignToken(mustList(t, 16, 1, map[int]byte{5: 1}), TokenClaims{Sub: e.srv.uri(), IssuedAt: e.now},
		SigningKey{Signer: signer, Alg: jose.AlgES256K, KID: kidA})
	if err != nil {
		t.Fatal(err)
	}
	e.srv.set(tok)
	if res, err := e.status(5); err != nil || res.Value != 1 {
		t.Fatalf("Status = %v, %v", res, err)
	}
}

// TestCheckerResolverInput: the key is asked for with the credential's iss
// and the token's kid, so the list must be signed by the credential's issuer.
func TestCheckerResolverInput(t *testing.T) {
	e := newEnv(t, Options{})
	e.serve(t, mustList(t, 16, 1, nil), TokenClaims{})
	if _, err := e.status(0); err != nil {
		t.Fatal(err)
	}
	if len(e.resolver.calls) != 1 || e.resolver.calls[0] != issA+" "+kidA {
		t.Fatalf("resolver calls %q, want [%q]", e.resolver.calls, issA+" "+kidA)
	}
}

// TestCheckerTraps: each failure is an error and no result, never a status.
func TestCheckerTraps(t *testing.T) {
	type setup func(t *testing.T, e *env)
	okClaims := func(e *env, extra string) string {
		lst, _ := mustList(t, 16, 1, nil).Encode()
		return `{"sub":"` + e.srv.uri() + `","iat":` + strconv.FormatInt(e.now.Unix(), 10) +
			`,"status_list":{"bits":1,"lst":"` + lst + `"}` + extra + `}`
	}
	hdr := map[string]any{"typ": TokenType, "kid": kidA}
	for _, tc := range []struct {
		name  string
		opts  Options
		setup setup
		index int
		want  error
	}{
		{"signed by another issuer's key", Options{}, func(t *testing.T, e *env) {
			tok, _ := SignToken(mustList(t, 16, 1, nil), TokenClaims{Sub: e.srv.uri(), IssuedAt: e.now},
				SigningKey{Signer: e.signerB, KID: kidA})
			e.srv.set(tok)
		}, 0, ErrTokenInvalid},
		{"payload altered after signing", Options{}, func(t *testing.T, e *env) {
			e.serve(t, mustList(t, 16, 1, nil), TokenClaims{})
			parts := strings.Split(e.srv.token, ".")
			lst, _ := mustList(t, 16, 1, map[int]byte{0: 1}).Encode()
			parts[1] = jose.EncodeSegment([]byte(`{"sub":"` + e.srv.uri() + `","iat":1,"status_list":{"bits":1,"lst":"` + lst + `"}}`))
			e.srv.set(strings.Join(parts, "."))
		}, 0, ErrTokenInvalid},
		{"resolver fails", Options{}, func(t *testing.T, e *env) {
			e.serve(t, mustList(t, 16, 1, nil), TokenClaims{})
			e.resolver.err = errors.New("no such kid")
		}, 0, ErrIssuerKey},
		{"resolver returns no key", Options{}, func(t *testing.T, e *env) {
			e.serve(t, mustList(t, 16, 1, nil), TokenClaims{})
			e.resolver.nilKey = true
		}, 0, ErrIssuerKey},
		{"alg not allowed", Options{AllowedAlgs: []string{jose.AlgES256K}}, func(t *testing.T, e *env) {
			e.serve(t, mustList(t, 16, 1, nil), TokenClaims{})
		}, 0, ErrTokenInvalid},
		{"typ jwt", Options{}, func(t *testing.T, e *env) {
			e.serveRaw(t, map[string]any{"typ": "JWT", "kid": kidA}, okClaims(e, ""))
		}, 0, ErrTokenInvalid},
		{"typ with application/ prefix", Options{}, func(t *testing.T, e *env) {
			e.serveRaw(t, map[string]any{"typ": MediaType, "kid": kidA}, okClaims(e, ""))
		}, 0, ErrTokenInvalid},
		{"no typ", Options{}, func(t *testing.T, e *env) {
			e.serveRaw(t, map[string]any{"kid": kidA}, okClaims(e, ""))
		}, 0, ErrTokenInvalid},
		{"sub differs from uri", Options{}, func(t *testing.T, e *env) {
			e.serve(t, mustList(t, 16, 1, nil), TokenClaims{Sub: e.srv.uri() + "/"})
		}, 0, ErrTokenInvalid},
		{"no sub", Options{}, func(t *testing.T, e *env) {
			e.serveRaw(t, hdr, strings.Replace(okClaims(e, ""), `"sub":"`+e.srv.uri()+`",`, "", 1))
		}, 0, ErrTokenInvalid},
		{"no iat", Options{}, func(t *testing.T, e *env) {
			e.serveRaw(t, hdr, strings.Replace(okClaims(e, ""), `"iat":`+strconv.FormatInt(e.now.Unix(), 10)+`,`, "", 1))
		}, 0, ErrTokenInvalid},
		{"iat a string", Options{}, func(t *testing.T, e *env) {
			e.serveRaw(t, hdr, strings.Replace(okClaims(e, ""), `"iat":`+strconv.FormatInt(e.now.Unix(), 10), `"iat":"1"`, 1))
		}, 0, ErrTokenInvalid},
		{"iat after now + skew", Options{}, func(t *testing.T, e *env) {
			e.serve(t, mustList(t, 16, 1, nil), TokenClaims{IssuedAt: e.now.Add(DefaultClockSkew + time.Second)})
		}, 0, ErrTokenInvalid},
		{"exp before now - skew", Options{}, func(t *testing.T, e *env) {
			e.serve(t, mustList(t, 16, 1, nil), TokenClaims{IssuedAt: e.now.Add(-time.Hour), Expiry: e.now.Add(-DefaultClockSkew - time.Second)})
		}, 0, ErrTokenInvalid},
		{"exp a string", Options{}, func(t *testing.T, e *env) {
			e.serveRaw(t, hdr, okClaims(e, `,"exp":"never"`))
		}, 0, ErrTokenInvalid},
		{"no status_list", Options{}, func(t *testing.T, e *env) {
			e.serveRaw(t, hdr, `{"sub":"`+e.srv.uri()+`","iat":`+strconv.FormatInt(e.now.Unix(), 10)+`}`)
		}, 0, ErrMalformed},
		{"bits 3", Options{}, func(t *testing.T, e *env) {
			e.serveRaw(t, hdr, strings.Replace(okClaims(e, ""), `"bits":1`, `"bits":3`, 1))
		}, 0, ErrMalformed},
		{"bits a string", Options{}, func(t *testing.T, e *env) {
			e.serveRaw(t, hdr, strings.Replace(okClaims(e, ""), `"bits":1`, `"bits":"1"`, 1))
		}, 0, ErrMalformed},
		{"bits 1.5", Options{}, func(t *testing.T, e *env) {
			e.serveRaw(t, hdr, strings.Replace(okClaims(e, ""), `"bits":1`, `"bits":1.5`, 1))
		}, 0, ErrMalformed},
		{"lst not a string", Options{}, func(t *testing.T, e *env) {
			e.serveRaw(t, hdr, `{"sub":"`+e.srv.uri()+`","iat":`+strconv.FormatInt(e.now.Unix(), 10)+`,"status_list":{"bits":1,"lst":7}}`)
		}, 0, ErrMalformed},
		{"lst inflates past MaxListBytes", Options{MaxListBytes: 100}, func(t *testing.T, e *env) {
			e.serve(t, mustList(t, 808, 1, nil), TokenClaims{})
		}, 0, ErrTooLarge},
		{"index outside the list", Options{}, func(t *testing.T, e *env) {
			e.serve(t, mustList(t, 16, 1, nil), TokenClaims{})
		}, 16, ErrIndexOutOfRange},
		{"ttl 0", Options{}, func(t *testing.T, e *env) { e.serveRaw(t, hdr, okClaims(e, `,"ttl":0`)) }, 0, ErrMalformed},
		{"ttl negative", Options{}, func(t *testing.T, e *env) { e.serveRaw(t, hdr, okClaims(e, `,"ttl":-60`)) }, 0, ErrMalformed},
		{"ttl a string", Options{}, func(t *testing.T, e *env) { e.serveRaw(t, hdr, okClaims(e, `,"ttl":"60"`)) }, 0, ErrMalformed},
		{"duplicate sub", Options{}, func(t *testing.T, e *env) {
			e.serveRaw(t, hdr, okClaims(e, `,"sub":"`+e.srv.uri()+`"`))
		}, 0, ErrMalformed},
		{"not a JWS", Options{}, func(t *testing.T, e *env) { e.srv.set("not-a-token") }, 0, ErrMalformed},
		{"Content-Type application/json", Options{}, func(t *testing.T, e *env) {
			e.serve(t, mustList(t, 16, 1, nil), TokenClaims{})
			e.srv.contentType = "application/json"
		}, 0, ErrFetch},
		{"Content-Type application/jwt", Options{}, func(t *testing.T, e *env) {
			e.serve(t, mustList(t, 16, 1, nil), TokenClaims{})
			e.srv.contentType = "application/jwt"
		}, 0, ErrFetch},
		{"status 404", Options{}, func(t *testing.T, e *env) {
			e.serve(t, mustList(t, 16, 1, nil), TokenClaims{})
			e.srv.status = http.StatusNotFound
		}, 0, ErrFetch},
		{"body over MaxBytes", Options{MaxBytes: 100}, func(t *testing.T, e *env) {
			e.serve(t, mustList(t, 16, 1, nil), TokenClaims{})
		}, 0, ErrFetch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, tc.opts)
			tc.setup(t, e)
			res, err := e.status(tc.index)
			if res != nil {
				t.Fatalf("a failure returned status %#x", res.Value)
			}
			wantErr(t, err, tc.want)
		})
	}
}

// TestCheckerTimeBoundaries: iat = now + skew and exp = now - skew are still
// accepted (statium's ensureIssuedBefore and ensureNotExpired).
func TestCheckerTimeBoundaries(t *testing.T) {
	e := newEnv(t, Options{})
	e.serve(t, mustList(t, 16, 1, nil), TokenClaims{IssuedAt: e.now.Add(DefaultClockSkew)})
	if _, err := e.status(0); err != nil {
		t.Errorf("iat = now + skew: %v", err)
	}
	e.serve(t, mustList(t, 16, 1, nil), TokenClaims{IssuedAt: e.now.Add(-time.Hour), Expiry: e.now.Add(-DefaultClockSkew)})
	if _, err := e.status(0); err != nil {
		t.Errorf("exp = now - skew: %v", err)
	}
	e2 := newEnv(t, Options{ClockSkew: 5 * time.Second})
	e2.serve(t, mustList(t, 16, 1, nil), TokenClaims{IssuedAt: e2.now.Add(6 * time.Second)})
	if _, err := e2.status(0); !errors.Is(err, ErrTokenInvalid) {
		t.Errorf("ClockSkew 5s, iat now+6s: %v, want ErrTokenInvalid", err)
	}
}

func TestCheckerFractionalTimes(t *testing.T) {
	e := newEnv(t, Options{})
	lst, _ := mustList(t, 16, 1, map[int]byte{2: 1}).Encode()
	e.serveRaw(t, map[string]any{"typ": TokenType, "kid": kidA},
		fmt.Sprintf(`{"sub":%q,"iat":%d.5,"exp":%d.25,"ttl":1.5e2,"status_list":{"bits":1,"lst":%q}}`,
			e.srv.uri(), e.now.Unix()-10, e.now.Unix()+3600, lst))
	if res, err := e.status(2); err != nil || res.Value != 1 {
		t.Fatalf("NumericDate with a fraction: %v, %v", res, err)
	}
}

func TestCheckerRefInput(t *testing.T) {
	e := newEnv(t, Options{})
	e.serve(t, mustList(t, 16, 1, nil), TokenClaims{})
	ctx := context.Background()
	for _, tc := range []struct {
		ref  Ref
		iss  string
		want error
	}{
		{Ref{URI: strings.Replace(e.srv.uri(), "https:", "http:", 1)}, issA, ErrInvalidArgument},
		{Ref{URI: "https:///x"}, issA, ErrInvalidArgument},
		{Ref{URI: e.srv.uri(), Index: -1}, issA, ErrIndexOutOfRange},
		{Ref{URI: e.srv.uri()}, "", ErrInvalidArgument},
	} {
		res, err := e.checker.Status(ctx, tc.ref, tc.iss, "")
		if res != nil {
			t.Fatalf("%+v: returned a status", tc.ref)
		}
		wantErr(t, err, tc.want)
	}
	if e.srv.count() != 0 {
		t.Errorf("invalid input caused %d fetches", e.srv.count())
	}
}

func TestNewCheckerRules(t *testing.T) {
	r := &resolver{}
	for name, o := range map[string]Options{
		"no Issuers":    {},
		"alg HS256":     {Issuers: r, AllowedAlgs: []string{"HS256"}},
		"alg none":      {Issuers: r, AllowedAlgs: []string{jose.AlgES256, "none"}},
		"negative skew": {Issuers: r, ClockSkew: -time.Second},
	} {
		if _, err := NewChecker(o); err == nil {
			t.Errorf("%s: accepted", name)
		} else {
			wantErr(t, err, ErrInvalidArgument)
		}
	}
}

func TestCheckerCacheByTTL(t *testing.T) {
	e := newEnv(t, Options{})
	e.serve(t, mustList(t, 16, 1, map[int]byte{3: 1}), TokenClaims{TTL: time.Minute})
	for i := 0; i < 3; i++ {
		if res, err := e.status(3); err != nil || res.Value != 1 {
			t.Fatalf("Status = %v, %v", res, err)
		}
	}
	if n := e.srv.count(); n != 1 {
		t.Fatalf("%d fetches within ttl, want 1", n)
	}
	// A cached list still answers index errors.
	if _, err := e.status(16); !errors.Is(err, ErrIndexOutOfRange) {
		t.Fatalf("cached list, index 16: %v", err)
	}
	e.now = e.now.Add(time.Minute)
	e.serve(t, mustList(t, 16, 1, map[int]byte{3: 0}), TokenClaims{TTL: time.Minute})
	if res, err := e.status(3); err != nil || res.Value != 0 {
		t.Fatalf("after ttl: %v, %v; want the new list", res, err)
	}
	if n := e.srv.count(); n != 2 {
		t.Fatalf("%d fetches after ttl, want 2", n)
	}
}

func TestCheckerNoTTLNoCache(t *testing.T) {
	e := newEnv(t, Options{})
	e.serve(t, mustList(t, 16, 1, nil), TokenClaims{})
	_, _ = e.status(0)
	_, _ = e.status(0)
	if n := e.srv.count(); n != 2 {
		t.Fatalf("%d fetches without ttl, want 2", n)
	}
}

func TestCheckerCacheCappedAt24h(t *testing.T) {
	e := newEnv(t, Options{})
	e.serve(t, mustList(t, 16, 1, nil), TokenClaims{TTL: 48 * time.Hour})
	_, _ = e.status(0)
	e.now = e.now.Add(24*time.Hour - time.Second)
	_, _ = e.status(0)
	if n := e.srv.count(); n != 1 {
		t.Fatalf("%d fetches before 24 h, want 1", n)
	}
	e.now = e.now.Add(time.Second)
	_, _ = e.status(0)
	if n := e.srv.count(); n != 2 {
		t.Fatalf("%d fetches at 24 h with ttl 48 h, want 2 (ttl is capped)", n)
	}
}

func TestCheckerCacheEndsAtExp(t *testing.T) {
	e := newEnv(t, Options{})
	e.serve(t, mustList(t, 16, 1, nil), TokenClaims{TTL: time.Hour, Expiry: e.now.Add(10 * time.Second)})
	_, _ = e.status(0)
	e.now = e.now.Add(10 * time.Second)
	_, _ = e.status(0)
	if n := e.srv.count(); n != 2 {
		t.Fatalf("%d fetches after exp, want 2 (a token is not cached past its exp)", n)
	}
}

func TestCheckerFailuresNotCached(t *testing.T) {
	e := newEnv(t, Options{})
	e.serve(t, mustList(t, 16, 1, nil), TokenClaims{TTL: time.Hour})
	e.srv.status = http.StatusServiceUnavailable
	if _, err := e.status(0); err == nil {
		t.Fatal("a 503 was accepted")
	}
	e.srv.status = http.StatusOK
	// A token that fails verification, though it carries a ttl, is not stored.
	tok, _ := SignToken(mustList(t, 16, 1, nil), TokenClaims{Sub: e.srv.uri(), IssuedAt: e.now, TTL: time.Hour},
		SigningKey{Signer: e.signerB, KID: kidA})
	e.srv.set(tok)
	if _, err := e.status(0); err == nil {
		t.Fatal("a token signed by another issuer was accepted")
	}
	e.serve(t, mustList(t, 16, 1, nil), TokenClaims{TTL: time.Hour})
	if _, err := e.status(0); err != nil {
		t.Fatalf("after recovery: %v", err)
	}
	if n := e.srv.count(); n != 3 {
		t.Fatalf("%d fetches, want 3: no failure may be served from the cache", n)
	}
}

// TestCheckerCacheKeyedByIssuer: a list cached for issuer A's credential must
// not answer for issuer B's credential pointing to the same uri, whose issuer
// did not sign it.
func TestCheckerCacheKeyedByIssuer(t *testing.T) {
	e := newEnv(t, Options{})
	e.serve(t, mustList(t, 16, 1, nil), TokenClaims{TTL: time.Hour})
	if _, err := e.status(0); err != nil {
		t.Fatal(err)
	}
	res, err := e.checker.Status(context.Background(), Ref{URI: e.srv.uri()}, issB, "")
	if res != nil || !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("issuer B, list signed by A: %v, %v; want ErrTokenInvalid", res, err)
	}
	if n := e.srv.count(); n != 2 {
		t.Fatalf("%d fetches, want 2", n)
	}
}

func TestCheckerCacheDisabled(t *testing.T) {
	e := newEnv(t, Options{MaxCacheBytes: -1})
	e.serve(t, mustList(t, 16, 1, nil), TokenClaims{TTL: time.Hour})
	_, _ = e.status(0)
	_, _ = e.status(0)
	if n := e.srv.count(); n != 2 {
		t.Fatalf("%d fetches with the cache disabled, want 2", n)
	}
}

func TestListCacheEviction(t *testing.T) {
	l := mustList(t, 8*10, 1, nil) // 10 bytes
	c := newListCache(3 * (10 + 1))
	far := t0.Add(time.Hour)
	c.put("a", l, far)
	c.put("b", l, far)
	c.put("c", l, far)
	if _, ok := c.get("a", t0); !ok { // a becomes the most recently used
		t.Fatal("a missing")
	}
	c.put("d", l, far) // evicts b, the least recently used
	if _, ok := c.get("b", t0); ok {
		t.Error("b should have been evicted")
	}
	for _, k := range []string{"a", "c", "d"} {
		if _, ok := c.get(k, t0); !ok {
			t.Errorf("%s missing", k)
		}
	}
	if c.used != 33 {
		t.Errorf("used %d, want 33", c.used)
	}
	c.put("big", mustList(t, 8*100, 1, nil), far)
	if _, ok := c.get("big", t0); ok {
		t.Error("an entry larger than the cache was stored")
	}
	if _, ok := c.get("a", far); ok {
		t.Error("an expired entry was returned")
	}
	if c.used != 22 {
		t.Errorf("used %d after expiry, want 22", c.used)
	}
}

func TestCheckerConcurrent(t *testing.T) {
	e := newEnv(t, Options{})
	e.serve(t, mustList(t, 64, 2, map[int]byte{7: 2}), TokenClaims{TTL: time.Hour})
	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := e.status(7)
			if err == nil && res.Value != 2 {
				err = fmt.Errorf("value %d", res.Value)
			}
			if err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// TestCheckerSSRF: the default client of NewChecker refuses a status list uri
// on, or resolving to, an internal address, and a redirect to one.
func TestCheckerSSRF(t *testing.T) {
	signer, pub := newP256(t)
	srv := newServer(t)
	port := srv.URL[strings.LastIndex(srv.URL, ":")+1:]
	r := &resolver{keys: map[string]*ecdsa.PublicKey{issA: pub}}
	c, err := NewChecker(Options{Issuers: r, Now: func() time.Time { return t0 }})
	if err != nil {
		t.Fatal(err)
	}
	for _, uri := range []string{
		srv.uri(),
		"https://localhost:" + port + "/statuslists/1",
		"https://10.0.0.5/statuslists/1",
		"https://169.254.169.254/statuslists/1",
		"https://[::ffff:10.0.0.5]/statuslists/1",
	} {
		res, err := c.Status(context.Background(), Ref{URI: uri}, issA, "")
		if res != nil || !errors.Is(err, ErrBlockedAddress) || !errors.Is(err, ErrFetch) {
			t.Errorf("%s: %v, %v; want ErrBlockedAddress", uri, res, err)
		}
	}
	if srv.count() != 0 {
		t.Errorf("a blocked uri reached the server %d times", srv.count())
	}

	// A redirect from an allowed server to another local port is refused at
	// the dialer.
	tok, _ := SignToken(mustList(t, 16, 1, nil), TokenClaims{Sub: srv.uri(), IssuedAt: t0}, SigningKey{Signer: signer, KID: kidA})
	srv.set(tok)
	redirector := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv.uri(), http.StatusFound)
	}))
	defer redirector.Close()
	c2, _ := NewChecker(Options{Issuers: r, Now: func() time.Time { return t0 }, HTTPClient: testClient(t, redirector)})
	res, err := c2.Status(context.Background(), Ref{URI: redirector.URL + "/statuslists/1"}, issA, "")
	if res != nil || !errors.Is(err, ErrBlockedAddress) {
		t.Errorf("redirect to a private address: %v, %v; want ErrBlockedAddress", res, err)
	}

	// The same client reaches the list when both servers are allowed, so the
	// refusal above is the address check and nothing else.
	c3, _ := NewChecker(Options{Issuers: r, Now: func() time.Time { return t0 }, HTTPClient: testClient(t, redirector, srv.Server)})
	if _, err := c3.Status(context.Background(), Ref{URI: srv.uri()}, issA, ""); err != nil {
		t.Errorf("allowed server: %v", err)
	}

	// Redirects to http are refused, and so are too many.
	loop := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/to-http" {
			http.Redirect(w, r, "http://"+r.Host+"/x", http.StatusFound)
			return
		}
		http.Redirect(w, r, r.URL.Path+"x", http.StatusFound)
	}))
	defer loop.Close()
	c4, _ := NewChecker(Options{Issuers: r, Now: func() time.Time { return t0 }, HTTPClient: testClient(t, loop)})
	for _, path := range []string{"/to-http", "/loop"} {
		_, err := c4.Status(context.Background(), Ref{URI: loop.URL + path}, issA, "")
		if !errors.Is(err, safehttp.ErrRedirect) || !errors.Is(err, ErrFetch) {
			t.Errorf("%s: %v, want a refused redirect", path, err)
		}
	}
}

func TestCheckerTimeout(t *testing.T) {
	release := make(chan struct{})
	slow := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer slow.Close()
	defer close(release)
	r := &resolver{}
	c, _ := NewChecker(Options{Issuers: r, Timeout: 100 * time.Millisecond, HTTPClient: testClient(t, slow)})
	start := time.Now()
	_, err := c.Status(context.Background(), Ref{URI: slow.URL + "/l"}, issA, "")
	if !errors.Is(err, ErrFetch) || time.Since(start) > 3*time.Second {
		t.Fatalf("slow server: %v after %v", err, time.Since(start))
	}
}

func TestCheckerDefaults(t *testing.T) {
	c, err := NewChecker(Options{Issuers: &resolver{}})
	if err != nil {
		t.Fatal(err)
	}
	if c.timeout != 5*time.Second || c.skew != time.Minute || c.maxBytes != 64<<10 ||
		c.maxListBytes != 16<<20 || c.cache == nil || c.cache.maxBytes != DefaultMaxCacheBytes ||
		len(c.allowedAlgs) != 2 {
		t.Fatalf("defaults: timeout %v, skew %v, maxBytes %d, maxListBytes %d, algs %v",
			c.timeout, c.skew, c.maxBytes, c.maxListBytes, c.allowedAlgs)
	}

	// The body limit is 64 KB by default: a token padded with whitespace to
	// exactly 64 KB is read, one byte more is refused.
	e := newEnv(t, Options{})
	e.serve(t, mustList(t, 16, 1, nil), TokenClaims{})
	tok := e.srv.token
	e.srv.set(tok + strings.Repeat(" ", 64<<10-len(tok)))
	if _, err := e.status(0); err != nil {
		t.Fatalf("64 KB body: %v", err)
	}
	e.srv.set(tok + strings.Repeat(" ", 64<<10-len(tok)+1))
	if _, err := e.status(0); !errors.Is(err, ErrFetch) || !errors.Is(err, safehttp.ErrTooLarge) {
		t.Fatalf("64 KB + 1 body: %v, want ErrFetch", err)
	}

	// The inflate limit is 16 MB by default.
	var buf strings.Builder
	buf.WriteString(`{"sub":"` + e.srv.uri() + `","iat":` + strconv.FormatInt(e.now.Unix(), 10) + `,"status_list":{"bits":1,"lst":"`)
	buf.WriteString(jose.EncodeSegment(zlibBytes(t, make([]byte, DefaultMaxListBytes+1))))
	buf.WriteString(`"}}`)
	e.serveRaw(t, map[string]any{"typ": TokenType, "kid": kidA}, buf.String())
	if _, err := e.status(0); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("lst of 16 MB + 1: %v, want ErrTooLarge", err)
	}
}
