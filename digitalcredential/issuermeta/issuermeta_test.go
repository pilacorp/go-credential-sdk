package issuermeta

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pilacorp/go-credential-sdk/digitalcredential/issuerkey"
	"github.com/pilacorp/go-credential-sdk/jose"
)

// The body of draft-ietf-oauth-sd-jwt-vc-19 §4.2 Figure 14, as printed.
const fig14 = `{
   "issuer":"https://example.com",
   "jwks":{
      "keys":[
         {
            "kid":"doc-signer-05-25-2022",
            "kty": "EC", "crv": "P-256",
            "x": "b28d4MwZMjw8-00CG4xfnn9SLMVMM19SlqZpVb_uNtQ",
            "y": "Xv5zWwuoaTgdS6hV43yI6gBwTnjukmFQQnJ_kCxzqk8"
         },
         {
            "kid":"doc-signer-06-05-2025",
            "kty": "EC", "crv": "P-256",
            "x":"DfjUx4WHBds61vGbqUQhsy3FGX13fAS13QWh2EHIkX8",
            "y":"NfqJt9Kp0EA93xq9ysO80DRZ_hCGlISz-pYLgv4RFvg"
         }
      ]
   }
}`

// The coordinates of the two keys of Figure 14.
const (
	p256AX = "b28d4MwZMjw8-00CG4xfnn9SLMVMM19SlqZpVb_uNtQ"
	p256AY = "Xv5zWwuoaTgdS6hV43yI6gBwTnjukmFQQnJ_kCxzqk8"
	p256BX = "DfjUx4WHBds61vGbqUQhsy3FGX13fAS13QWh2EHIkX8"
	p256BY = "NfqJt9Kp0EA93xq9ysO80DRZ_hCGlISz-pYLgv4RFvg"
)

// twoKeys is the jwks of Figure 14.
const twoKeys = `{"keys":[
	{"kid":"doc-signer-05-25-2022","kty":"EC","crv":"P-256","x":"` + p256AX + `","y":"` + p256AY + `"},
	{"kid":"doc-signer-06-05-2025","kty":"EC","crv":"P-256","x":"` + p256BX + `","y":"` + p256BY + `"}
]}`

type response struct {
	contentType, cacheControl, body string
}

// metaServer serves routes[path]. Its client reaches it for any host name,
// so the identifiers of the draft (example.com, which the httptest
// certificate names) can be used as they are.
type metaServer struct {
	routes     map[string]response
	redirects  map[string]string // path to the target of a 302
	hits       atomic.Int32
	redirected atomic.Int32 // requests answered with a 302
	moved      atomic.Int32 // requests for /moved
	srv        *httptest.Server
}

func newMetaServer(t *testing.T, routes map[string]response) *metaServer {
	t.Helper()
	s := &metaServer{routes: routes}
	s.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		if r.URL.Path == "/moved" {
			s.moved.Add(1)
		}
		if loc, ok := s.redirects[r.URL.Path]; ok {
			s.redirected.Add(1)
			http.Redirect(w, r, loc, http.StatusFound)
			return
		}
		resp, ok := s.routes[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", resp.contentType)
		if resp.cacheControl != "" {
			w.Header().Set("Cache-Control", resp.cacheControl)
		}
		w.Write([]byte(resp.body))
	}))
	t.Cleanup(s.srv.Close)
	return s
}

// resolver returns a Resolver over s whose clock reads *now.
func (s *metaServer) resolver(t *testing.T, allowed []string, now *time.Time, disableCache bool) *Resolver {
	t.Helper()
	return s.resolverFor(t, Config{TrustedIssuerOrigins: allowed, DisableCache: disableCache}, now)
}

// resolverFor returns a Resolver for cfg over s whose clock reads *now.
func (s *metaServer) resolverFor(t *testing.T, cfg Config, now *time.Time) *Resolver {
	t.Helper()
	client := s.srv.Client()
	addr := s.srv.Listener.Addr().String()
	client.Transport.(*http.Transport).DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	cfg.HTTPClient = client
	r, err := NewResolver(cfg)
	if err != nil {
		t.Fatal(err)
	}
	r.now = func() time.Time { return *now }
	return r
}

func metadata(issuer, jwks string) response {
	return response{"application/json", "max-age=3600", `{"issuer":"` + issuer + `","jwks":` + jwks + `}`}
}

func ecKey(t *testing.T, k issuerkey.PublicKey) *ecdsa.PublicKey {
	t.Helper()
	pub, ok := k.Public.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("key %q is a %T, want *ecdsa.PublicKey", k.KID, k.Public)
	}
	return pub
}

func decodeCoord(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// draft-ietf-oauth-sd-jwt-vc-19 §4.1 Figures 12 and 13, and a terminating
// "/" removed.
func TestMetadataURL(t *testing.T) {
	for iss, want := range map[string]string{
		"https://example.com":             "https://example.com/.well-known/jwt-vc-issuer",
		"https://example.com/tenant/1234": "https://example.com/.well-known/jwt-vc-issuer/tenant/1234",
		"https://example.com/":            "https://example.com/.well-known/jwt-vc-issuer",
		// Not dot-segments, and kept as written.
		"https://example.com/a..b/.c/d.": "https://example.com/.well-known/jwt-vc-issuer/a..b/.c/d.",
		"https://example.com/.../-/*":    "https://example.com/.well-known/jwt-vc-issuer/.../-/*",
		"https://example.com/a%2Fb":      "https://example.com/.well-known/jwt-vc-issuer/a%2Fb",
		"https://example.com/a;b":        "https://example.com/.well-known/jwt-vc-issuer/a;b",
		"https://example.com/100%25":     "https://example.com/.well-known/jwt-vc-issuer/100%25",
		"https://example.com/tenant:1":   "https://example.com/.well-known/jwt-vc-issuer/tenant:1",
		// One decode gives "%2e%2e", a plain segment: RFC 3986 §2.4 forbids a
		// second, and README sends a double-decoding front to WithAcceptedIssuers.
		"https://example.com/%252e%252e": "https://example.com/.well-known/jwt-vc-issuer/%252e%252e",
	} {
		if got, err := MetadataURL(iss); err != nil || got != want {
			t.Errorf("MetadataURL(%q) = %q, %v; want %q", iss, got, err, want)
		}
	}
}

// draft-ietf-oauth-sd-jwt-vc-20 §4: no dot-segment in the path of iss, raw or
// percent-encoded (RFC 3986 §2.3, §6.2.2.3). Separators in %2F and %5C and a
// ";" parameter are forms servers resolve the same way. Each would reach a
// file outside /.well-known/; each is refused before any request.
func TestDotSegmentsRefused(t *testing.T) {
	s := newMetaServer(t, nil)
	now := time.Unix(1_800_000_000, 0)
	r := s.resolver(t, nil, &now, false)
	for _, path := range []string{
		"/..", "/.", "/a/..", "/./x", "/../../uploads/keys.json",
		"/%2e%2e/%2E%2E/uploads/keys.json", "/.%2E/%2e./uploads/keys.json",
		"/..%2f..%2fuploads%2fkeys.json", "/%2e%2e%2F%2e%2e%2Fuploads%2Fkeys.json",
		"/..%5c..%5cuploads%5ckeys.json", "/..;/..;/uploads/keys.json", "/..;x/uploads/keys.json",
	} {
		iss := "https://example.com" + path
		if got, err := MetadataURL(iss); !errors.Is(err, issuerkey.ErrIssuerNotSupported) {
			t.Errorf("MetadataURL(%q) = %q, %v; want ErrIssuerNotSupported", iss, got, err)
		}
		if _, err := r.Keys(context.Background(), iss); !errors.Is(err, issuerkey.ErrIssuerNotSupported) {
			t.Errorf("Keys(%q) = %v, want ErrIssuerNotSupported", iss, err)
		}
	}
	if n := s.hits.Load(); n != 0 {
		t.Fatalf("server got %d requests, want 0", n)
	}
}

// Figure 14: inline jwks, Cache-Control max-age=3600. Both keys are
// returned in order, reused until 3600 s, then fetched again; DisableCache
// fetches every time.
func TestFigure14(t *testing.T) {
	s := newMetaServer(t, map[string]response{"/.well-known/jwt-vc-issuer": {"application/json", "max-age=3600", fig14}})
	now := time.Unix(1_800_000_000, 0)
	r := s.resolver(t, []string{"https://example.com"}, &now, false)
	keys, err := r.Keys(context.Background(), "https://example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || keys[0].KID != "doc-signer-05-25-2022" || keys[1].KID != "doc-signer-06-05-2025" ||
		!bytes.Equal(ecKey(t, keys[0]).X.FillBytes(make([]byte, 32)), decodeCoord(t, p256AX)) ||
		!bytes.Equal(ecKey(t, keys[1]).X.FillBytes(make([]byte, 32)), decodeCoord(t, p256BX)) {
		t.Fatalf("keys = %+v, want the two keys of Figure 14 in order", keys)
	}
	now = now.Add(3599 * time.Second)
	if _, err := r.Keys(context.Background(), "https://example.com"); err != nil || s.hits.Load() != 1 {
		t.Fatalf("at 3599 s: err = %v, hits = %d; want a cache hit", err, s.hits.Load())
	}
	now = now.Add(time.Second)
	if _, err := r.Keys(context.Background(), "https://example.com"); err != nil || s.hits.Load() != 2 {
		t.Fatalf("at 3600 s: err = %v, hits = %d; want a refetch", err, s.hits.Load())
	}

	nc := s.resolver(t, []string{"https://example.com"}, &now, true)
	for range 2 {
		if _, err := nc.Keys(context.Background(), "https://example.com"); err != nil {
			t.Fatal(err)
		}
	}
	if n := s.hits.Load(); n != 4 {
		t.Fatalf("DisableCache: hits = %d, want 4", n)
	}
}

// A max-age past 24 hours is cut to 24 hours, so a key the issuer removes
// stops verifying within a day.
func TestCacheAtMost24Hours(t *testing.T) {
	s := newMetaServer(t, map[string]response{"/.well-known/jwt-vc-issuer": {"application/json", "max-age=31536000", fig14}})
	start := time.Unix(1_800_000_000, 0)
	now := start
	r := s.resolver(t, []string{"https://example.com"}, &now, false)
	for _, at := range []time.Duration{0, 24*time.Hour - time.Second, 24 * time.Hour} {
		now = start.Add(at)
		if _, err := r.Keys(context.Background(), "https://example.com"); err != nil {
			t.Fatalf("Keys at +%v: %v", at, err)
		}
	}
	if n := s.hits.Load(); n != 2 {
		t.Errorf("server got %d requests, want 2 (cached until +24h, fetched again at +24h)", n)
	}
}

// Figure 15: jwks_uri, its JWK Set served as application/jwk-set+json with
// max-age=60 against the metadata's 3600: the shorter one decides.
func TestFigure15(t *testing.T) {
	s := newMetaServer(t, map[string]response{
		"/.well-known/jwt-vc-issuer": {"application/json", "max-age=3600", `{"issuer":"https://example.com","jwks_uri":"https://jwt-vc-issuer.example.com/my_public_keys.jwks"}`},
		"/my_public_keys.jwks":       {"application/jwk-set+json", "max-age=60", twoKeys},
	})
	now := time.Unix(1_800_000_000, 0)
	r := s.resolver(t, []string{"https://example.com"}, &now, false)
	keys, err := r.Keys(context.Background(), "https://example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || keys[0].KID != "doc-signer-05-25-2022" || keys[1].KID != "doc-signer-06-05-2025" ||
		!bytes.Equal(ecKey(t, keys[0]).X.FillBytes(make([]byte, 32)), decodeCoord(t, p256AX)) {
		t.Fatalf("keys = %+v, want both keys of the set in order", keys)
	}
	now = now.Add(59 * time.Second)
	if _, err := r.Keys(context.Background(), "https://example.com"); err != nil || s.hits.Load() != 2 {
		t.Fatalf("at 59 s: err = %v, hits = %d; want a cache hit", err, s.hits.Load())
	}
	now = now.Add(time.Second)
	if _, err := r.Keys(context.Background(), "https://example.com"); err != nil || s.hits.Load() != 4 {
		t.Fatalf("at 60 s: err = %v, hits = %d; want both documents fetched again", err, s.hits.Load())
	}
}

func TestNewResolver(t *testing.T) {
	// An empty TrustedIssuerOrigins trusts every https issuer.
	if _, err := NewResolver(Config{}); err != nil {
		t.Fatalf("NewResolver(Config{}) = %v", err)
	}
	for _, e := range []string{
		// Not https, or no host.
		"https:/", "http://example.com", "example.com", "https://",
		// A "*" in a host other than a single leading "*." of an origin.
		"**", "https://*", "https://a*.example.com/", "https://*.*.example.com/", "https://*example.com/",
		"https://*.example.com/x", "https://user@*.example.com/", "https://*.example.com?x",
		// Not an origin: a path, query, fragment or userinfo.
		"https://example.com/tenant/", "https://example.com/tenant", "https://example.com/a*b",
		"https://example.com?x=*", "https://example.com/?x=/", "https://example.com/#x", "https://user@example.com/",
		// A host or port that would not match the URL it means: an empty
		// label, a final "." included, a host not in ASCII, raw or
		// percent-encoded, or a port with a leading zero or out of range.
		"https://example.com.", "https://*.example.com./", "https://bücher.example", "https://b%C3%BCcher.example",
		"https://.example.com", "https://a..example.com", "https://*..example.com",
		"https://example.com:0443", "https://example.com:0", "https://example.com:65536",
		// "*": an empty list covers every origin.
		"*",
	} {
		if _, err := NewResolver(Config{TrustedIssuerOrigins: []string{"https://ok.example/", e}}); !errors.Is(err, jose.ErrInvalidArgument) {
			t.Errorf("NewResolver(%q) = %v, want jose.ErrInvalidArgument", e, err)
		}
		if _, err := NewResolver(Config{Redirects: RedirectTo("https://ok.example/", e)}); !errors.Is(err, jose.ErrInvalidArgument) || !strings.Contains(err.Error(), "RedirectTo[1]") {
			t.Errorf("RedirectTo(%q) = %v, want jose.ErrInvalidArgument naming RedirectTo[1]", e, err)
		}
	}
	if _, err := NewResolver(Config{TrustedIssuerOrigins: []string{"https://example.com/tenant/"}}); err == nil || !strings.Contains(err.Error(), "Resolver that wraps this one") {
		t.Errorf("NewResolver(path) = %v, want the text to point to a wrapping Resolver", err)
	}
	if _, err := NewResolver(Config{TrustedIssuerOrigins: []string{"*"}}); err == nil || !strings.Contains(err.Error(), "leave Config.TrustedIssuerOrigins empty") {
		t.Errorf(`NewResolver("*") = %v, want the text to point to an empty list`, err)
	}
	if _, err := NewResolver(Config{Redirects: RedirectTo("*")}); err == nil || !strings.Contains(err.Error(), "RedirectAny") {
		t.Errorf(`RedirectTo("*") = %v, want the text to point to RedirectAny`, err)
	}
	if _, err := NewResolver(Config{Redirects: RedirectTo()}); !errors.Is(err, jose.ErrInvalidArgument) {
		t.Errorf("RedirectTo() = %v, want jose.ErrInvalidArgument", err)
	}
	for _, e := range []string{"https://example.com/", "https://example.com", "https://EXAMPLE.com:443", "https://example.com:8443/",
		"https://xn--bcher-kva.example", "https://*.example.com", "https://*.example.com/", "https://*.example.com:8443/"} {
		if _, err := NewResolver(Config{TrustedIssuerOrigins: []string{e}, Redirects: RedirectTo(e)}); err != nil {
			t.Errorf("NewResolver(%q) = %v", e, err)
		}
	}
	if _, err := NewResolver(Config{Redirects: RedirectAny()}); err != nil {
		t.Errorf("RedirectAny: %v", err)
	}
}

// The cache holds at most maxCacheBytes (SDK policy): a store that does not
// fit is refused, so distinct issuers cannot grow memory without bound.
func TestCacheBudget(t *testing.T) {
	r, err := NewResolver(Config{})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	r.now = func() time.Time { return now }
	// Expired when big is stored: the full cache drops it, and big fits.
	r.store("https://old", nil, now, now.Add(time.Second))
	now = now.Add(2 * time.Second)
	// Fills the budget to within 100 bytes, less than any entry costs.
	big := "https://a/" + strings.Repeat("a", maxCacheBytes-entryCost-110)
	r.store(big, nil, now, now.Add(time.Hour))
	r.store("https://b", nil, now, now.Add(time.Hour))
	if _, ok := r.cached(big); !ok {
		t.Fatal("entry within the budget not cached")
	}
	if _, ok := r.cached("https://b"); ok {
		t.Fatal("entry over the budget cached")
	}
}

// draft 19 §2.5 and §4: no iss, userinfo (RFC 9110 §4.2.4), an empty query.
// Refused before any request.
func TestKeysRefused(t *testing.T) {
	s := newMetaServer(t, nil)
	now := time.Unix(1_800_000_000, 0)
	r := s.resolver(t, nil, &now, false)
	for _, iss := range []string{"", "https://user@example.com", "https://example.com?", "https://bücher.example", "https:///issuer", "https:x"} {
		if _, err := r.Keys(context.Background(), iss); !errors.Is(err, issuerkey.ErrIssuerNotSupported) {
			t.Errorf("Keys(%q) = %v, want ErrIssuerNotSupported", iss, err)
		}
	}
	if n := s.hits.Load(); n != 0 {
		t.Fatalf("server got %d requests, want 0", n)
	}
}

// An origin entry, with or without its final "/", covers every iss of its
// origin, and a subdomain entry every iss of a subdomain, the host in any
// case and the default port implied (RFC 6454 §4); an empty
// TrustedIssuerOrigins covers every iss. An iss not covered is refused
// before any request, whatever Redirects follows.
func TestTrustedIssuerOrigins(t *testing.T) {
	covered := []string{"https://example.com", "https://example.com/tenant/1", "https://EXAMPLE.com:443/tenant/2", "https://example.com/tenant/caf%C3%A9"}
	subdomains := []string{"https://a.example.com/sub/1", "https://B.example.com:443/sub/2"}
	routes := map[string]response{}
	for _, iss := range append(covered, subdomains...) {
		u, _ := MetadataURL(iss)
		pu, _ := url.Parse(u)
		routes[pu.Path] = metadata(iss, twoKeys)
	}
	now := time.Unix(1_800_000_000, 0)
	for _, tc := range []struct {
		name             string
		allowed          []string
		covered, refused []string
	}{
		{"empty", nil, append(covered, subdomains...), nil},
		{"subdomain", []string{"https://*.example.com"}, subdomains, []string{
			"https://example.com/tenant/1",
			"https://evilexample.com/sub/1",
			"https://a.example.com.evil/sub/1",
			"https://a.example.com:8443/sub/1",
			"https://attacker.example/a.example.com",
			"https://attacker.example/.example.com",
			"https://[2001:db8::1%25.example.com]/sub/1",
		}},
		{"origin", []string{"https://example.com/"}, covered, []string{"https://example.org/tenant/1", "https://example.com:8443/tenant/1", "https://sub.example.com/tenant/1"}},
		{"origin without the final /", []string{"https://example.com"}, covered, []string{"https://example.org/tenant/1", "https://example.com:8443/tenant/1", "https://sub.example.com/tenant/1"}},
		{"origin with its default port", []string{"https://EXAMPLE.com:443"}, covered, []string{"https://example.com:8443/tenant/1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newMetaServer(t, routes)
			r := s.resolverFor(t, Config{TrustedIssuerOrigins: tc.allowed, Redirects: RedirectAny()}, &now)
			for _, iss := range tc.refused {
				if _, err := r.Keys(context.Background(), iss); !errors.Is(err, issuerkey.ErrIssuerNotSupported) {
					t.Errorf("Keys(%q) = %v, want ErrIssuerNotSupported", iss, err)
				}
			}
			if n := s.hits.Load(); n != 0 {
				t.Fatalf("refused iss: server got %d requests, want 0", n)
			}
			for _, iss := range tc.covered {
				if keys, err := r.Keys(context.Background(), iss); err != nil || len(keys) != 2 {
					t.Errorf("Keys(%q) = %d keys, %v; want 2 keys", iss, len(keys), err)
				}
			}
		})
	}
}

// draft 19 §4.3: metadata whose issuer differs from iss, here by a
// terminating "/", must not be used, and the answer is not cached.
func TestIssuerMismatch(t *testing.T) {
	s := newMetaServer(t, map[string]response{
		"/.well-known/jwt-vc-issuer/tenant/1234": metadata("https://example.com/tenant/1234/", twoKeys),
	})
	now := time.Unix(1_800_000_000, 0)
	r := s.resolver(t, []string{"https://example.com/"}, &now, false)
	for i := range 2 {
		if _, err := r.Keys(context.Background(), "https://example.com/tenant/1234"); !errors.Is(err, issuerkey.ErrNoUsableKey) {
			t.Fatalf("call %d: err = %v, want ErrNoUsableKey", i+1, err)
		}
	}
	if n := s.hits.Load(); n != 2 {
		t.Fatalf("hits = %d, want 2", n)
	}
}

// draft 19 §3: a jwks_uri that is not https is a fault of the metadata, and
// no JWK Set is requested.
func TestJWKSURIHTTP(t *testing.T) {
	for _, jwksURI := range []string{"http://example.com/jwks", "https://bücher.example/jwks"} {
		s := newMetaServer(t, map[string]response{
			"/.well-known/jwt-vc-issuer": {"application/json", "", `{"issuer":"https://example.com","jwks_uri":"` + jwksURI + `"}`},
			"/jwks":                      {"application/json", "", twoKeys},
		})
		now := time.Unix(1_800_000_000, 0)
		r := s.resolver(t, []string{"https://example.com"}, &now, false)
		if _, err := r.Keys(context.Background(), "https://example.com"); !errors.Is(err, issuerkey.ErrNoUsableKey) {
			t.Fatalf("%s: err = %v, want ErrNoUsableKey", jwksURI, err)
		}
		if n := s.hits.Load(); n != 1 {
			t.Fatalf("%s: hits = %d, want 1 (the metadata only)", jwksURI, n)
		}
	}
}

// draft 19 §7.1: the default client refuses the loopback address the
// httptest server listens on.
func TestDefaultClientRefusesLoopback(t *testing.T) {
	s := newMetaServer(t, nil)
	r, err := NewResolver(Config{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Keys(context.Background(), s.srv.URL); !errors.Is(err, ErrAddressBlocked) {
		t.Fatalf("err = %v, want ErrAddressBlocked", err)
	}
	if n := s.hits.Load(); n != 0 {
		t.Fatalf("hits = %d, want 0", n)
	}
}

// A metadata body over 64 KiB is a failed retrieval, not a document to judge.
func TestBodyOverCap(t *testing.T) {
	body := `{"issuer":"https://example.com","jwks":{"keys":[]},"pad":"` + strings.Repeat("a", 64<<10) + `"}`
	s := newMetaServer(t, map[string]response{"/.well-known/jwt-vc-issuer": {"application/json", "", body}})
	now := time.Unix(1_800_000_000, 0)
	r := s.resolver(t, []string{"https://example.com"}, &now, false)
	_, err := r.Keys(context.Background(), "https://example.com")
	if !errors.Is(err, ErrBodyTooLarge) || errors.Is(err, issuerkey.ErrNoUsableKey) || errors.Is(err, issuerkey.ErrIssuerNotSupported) {
		t.Fatalf("err = %v, want ErrBodyTooLarge, a retrieval error", err)
	}
}

// A status that is not 2xx is a failed retrieval, not a document to judge,
// and its code reaches the caller.
func TestStatusNot2xx(t *testing.T) {
	s := newMetaServer(t, nil)
	now := time.Unix(1_800_000_000, 0)
	r := s.resolver(t, []string{"https://example.com"}, &now, false)
	_, err := r.Keys(context.Background(), "https://example.com")
	var se *StatusError
	if !errors.As(err, &se) || se.Code != http.StatusNotFound || errors.Is(err, issuerkey.ErrNoUsableKey) {
		t.Fatalf("err = %v, want a StatusError with code 404, a retrieval error", err)
	}
}

// draft 19 §3: a redirect to http is refused before Redirects is asked, so
// the refusal is ErrRedirectTargetNotAllowed, not ErrRedirectNotAllowed.
func TestRedirectToHTTP(t *testing.T) {
	s := newMetaServer(t, map[string]response{"/moved": metadata("https://example.com", twoKeys)})
	s.redirects = map[string]string{"/.well-known/jwt-vc-issuer": "http://example.com/moved"}
	now := time.Unix(1_800_000_000, 0)
	r := s.resolverFor(t, Config{}, &now)
	_, err := r.Keys(context.Background(), "https://example.com")
	if !errors.Is(err, ErrRedirectTargetNotAllowed) || errors.Is(err, ErrRedirectNotAllowed) {
		t.Fatalf("err = %v, want ErrRedirectTargetNotAllowed only", err)
	}
}

// RFC 7517 §5: a JWK this resolver cannot use is skipped: another kty, a key
// for encryption (use, §4.2), for key agreement (key_ops, §4.3), for another
// alg (§4.4; RFC 8725 §3.1). A key without kid is kept, and so is a secp256k1
// key. An element that is not a JWK object (§4) makes the set invalid.
func TestKeyWalk(t *testing.T) {
	ec := func(extra string) string {
		return `{"kty":"EC","crv":"P-256","x":"` + p256AX + `","y":"` + p256AY + `"` + extra + `}`
	}
	decode := func(s string) map[string]any {
		m, err := jose.DecodeJSONObject([]byte(s))
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	keys, err := signingKeys(decode(`{"keys":[
		{"kty":"RSA","e":"AQAB","n":"nj3YJwsLUFl9BmpAbkOswCNVx17Eh9wMO-_AReZwBqfaWFcfGHrZXsIV2VMCNVNU8Tpb4obUaSXcRcQ"},
		` + ec(`,"kid":"enc","use":"enc"`) + `,
		` + ec(`,"kid":"ecdh","key_ops":["deriveKey"]`) + `,
		` + ec(`,"kid":"k1","alg":"ES256K"`) + `,
		{"kty":"EC","crv":"P-256","x":"` + p256BX + `","y":"` + p256BY + `","use":"sig","alg":"ES256","key_ops":["verify"]},
		{"kty":"EC","crv":"secp256k1","x":"eb5mfvncu6xVoGKVzocLBwKb_NstzijZWfKBWxb4F5g","y":"SDradyajxGVdpPv8DhEIqP0XtEimhVQZnEfQj_sQ1Lg","kid":"k1s","alg":"ES256K"}
	]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || keys[0].KID != "" || !bytes.Equal(ecKey(t, keys[0]).X.FillBytes(make([]byte, 32)), decodeCoord(t, p256BX)) || keys[1].KID != "k1s" {
		t.Fatalf("keys = %+v, want the P-256 signing key without kid, then the secp256k1 key k1s", keys)
	}

	if _, err := signingKeys(decode(`{"keys":[` + ec("") + `,"x"]}`)); !errors.Is(err, issuerkey.ErrNoUsableKey) {
		t.Errorf("non-object element: err = %v, want ErrNoUsableKey", err)
	}
	if keys, err := signingKeys(decode(`{"keys":[` + ec(`,"use":"enc"`) + `]}`)); err != nil || keys == nil || len(keys) != 0 {
		t.Errorf("no usable key: keys = %v, err = %v; want an empty slice", keys, err)
	}
}

// The credential chooses the path of iss, so by default every redirect, of
// the metadata and of jwks_uri, stays on the origin of the URL requested
// whatever TrustedIssuerOrigins holds: another origin is refused before it
// is requested, and the failure is not cached. RedirectTo adds the origins
// it lists to that origin, and RedirectAny follows any https URL.
func TestRedirects(t *testing.T) {
	const iss = "https://example.com/tenant/1"
	const origin = "https://example.com/"
	byURI := response{"application/json", "max-age=3600", `{"issuer":"` + iss + `","jwks_uri":"https://example.com/jwks"}`}
	jwkSet := response{"application/jwk-set+json", "", twoKeys}
	// The test client dials every host to the test server, whose
	// certificate covers example.com on any port: example.com:8443 is
	// another origin the redirect can reach.
	const other = "https://example.com:8443/moved"
	for _, tc := range []struct {
		name      string
		allowed   []string
		redirects RedirectPolicy
		jwksURI   bool // the redirect answers jwks_uri, not the metadata
		location  string
		refused   bool
	}{
		// Refused before any connection, so the test certificate, which
		// covers only example.com, is never asked for this name.
		{"another hostname", []string{origin}, RedirectPolicy{}, false, "https://other.example/moved", true},
		{"another port", []string{origin}, RedirectPolicy{}, false, other, true},
		{"another port, both origins listed", []string{origin, "https://example.com:8443"}, RedirectPolicy{}, false, other, true},
		{"empty TrustedIssuerOrigins, another port", nil, RedirectPolicy{}, false, other, true},
		{"jwks_uri to another port", nil, RedirectPolicy{}, true, other, true},
		{"same origin, another case and default port", []string{origin}, RedirectPolicy{}, false, "https://EXAMPLE.com:443/moved", false},
		{"jwks_uri, same origin", nil, RedirectPolicy{}, true, "https://example.com/moved", false},
		{"RedirectTo the target", []string{origin}, RedirectTo("https://example.com:9443", "https://EXAMPLE.com:8443/"), false, other, false},
		{"RedirectTo another origin", []string{origin}, RedirectTo("https://example.com:9443"), false, other, true},
		{"RedirectTo, same origin", []string{origin}, RedirectTo("https://example.com:9443"), false, "https://example.com/moved", false},
		{"RedirectTo, jwks_uri to the target", nil, RedirectTo("https://example.com:8443"), true, other, false},
		{"RedirectAny", []string{origin}, RedirectAny(), false, other, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			routes, from := map[string]response{"/moved": metadata(iss, twoKeys)}, "/.well-known/jwt-vc-issuer/tenant/1"
			if tc.jwksURI {
				routes, from = map[string]response{from: byURI, "/moved": jwkSet}, "/jwks"
			}
			s := newMetaServer(t, routes)
			s.redirects = map[string]string{from: tc.location}
			now := time.Unix(1_800_000_000, 0)
			r := s.resolverFor(t, Config{TrustedIssuerOrigins: tc.allowed, Redirects: tc.redirects}, &now)
			for range 2 {
				_, err := r.Keys(context.Background(), iss)
				switch {
				// The refusal, not a TLS failure to reach the other name, and
				// the text says how the issuer or the verifier fixes it.
				case tc.refused && (!errors.Is(err, ErrRedirectNotAllowed) || !strings.Contains(err.Error(), "must serve it from that origin, or the verifier allows the target with RedirectTo")):
					t.Fatalf("err = %v, want the redirect refused", err)
				case !tc.refused && err != nil:
					t.Fatalf("err = %v, want the redirect followed", err)
				}
			}
			// Each call requests the redirect again: a refusal is not cached,
			// and a 302 without freshness keeps a followed answer out too.
			want := int32(2)
			if tc.refused {
				want = 0
			}
			if redirects, moved := s.redirected.Load(), s.moved.Load(); redirects != 2 || moved != want {
				t.Fatalf("redirect got %d requests, target %d; want 2 and %d", redirects, moved, want)
			}
		})
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// A did: iss is valid, only not this resolver's: the text must say what to
// supply, and the refusal comes before any request.
func TestKeysNamesTheDIDResolverForADID(t *testing.T) {
	r, err := NewResolver(Config{HTTPClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("no request is sent for a did: iss")
		return nil, nil
	})}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.Keys(context.Background(), "did:example:123")
	want := "issuerkey: issuer not supported: issuermeta: iss is a DID; use didresolver for a DID iss"
	if !errors.Is(err, issuerkey.ErrIssuerNotSupported) || err.Error() != want {
		t.Errorf("err = %v; want %q", err, want)
	}
}
