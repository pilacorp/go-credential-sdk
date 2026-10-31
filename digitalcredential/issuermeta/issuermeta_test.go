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
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pilacorp/go-credential-sdk/digitalcredential/internal/safehttp"
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
	routes map[string]response
	hits   atomic.Int32
	srv    *httptest.Server
}

func newMetaServer(t *testing.T, routes map[string]response) *metaServer {
	t.Helper()
	s := &metaServer{routes: routes}
	s.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
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
	client := s.srv.Client()
	addr := s.srv.Listener.Addr().String()
	client.Transport.(*http.Transport).DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	r, err := NewResolver(Config{Allowed: allowed, HTTPClient: client, DisableCache: disableCache})
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
	} {
		if got, err := MetadataURL(iss); err != nil || got != want {
			t.Errorf("MetadataURL(%q) = %q, %v; want %q", iss, got, err, want)
		}
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

// RFC 9111 §5.2.2.4, §5.2.2.5, §4.1, §4.2.1, §4.2.3, §1.2.2, and a
// quoted-string argument that holds a max-age.
func TestFreshness(t *testing.T) {
	for _, c := range []struct {
		name               string
		cacheControl, vary string
		age                string
		want               time.Duration
	}{
		{"no-store", "max-age=600, no-store", "", "", 0},
		{"no-cache", "no-cache, max-age=600", "", "", 0},
		{"Vary not set by the Resolver", "max-age=600", "Accept, Cookie", "", 0},
		{"Age 100", "max-age=600", "", "100", 500 * time.Second},
		{"Age = max-age", "max-age=600", "", "600", 0},
		{"over 24 h", "max-age=9223372037", "", "", 24 * time.Hour},
		{"quoted max-age", `x-ext=", max-age=86400, "`, "", "", 0},
	} {
		h := http.Header{"Cache-Control": {c.cacheControl}}
		if c.vary != "" {
			h.Set("Vary", c.vary)
		}
		if c.age != "" {
			h.Set("Age", c.age)
		}
		if got := freshness(h); got != c.want {
			t.Errorf("%s: freshness = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestNewResolver(t *testing.T) {
	if _, err := NewResolver(Config{}); !errors.Is(err, jose.ErrInvalidArgument) {
		t.Fatalf("NewResolver(Config{}) = %v, want jose.ErrInvalidArgument", err)
	}
	// A typo of "https://" that would cover every https iss.
	if _, err := NewResolver(Config{Allowed: []string{"https:/"}}); !errors.Is(err, jose.ErrInvalidArgument) {
		t.Fatalf(`NewResolver("https:/") = %v, want jose.ErrInvalidArgument`, err)
	}
}

// The cache holds at most maxCacheBytes (SDK policy): a store that does not
// fit is refused, so distinct issuers cannot grow memory without bound.
func TestCacheBudget(t *testing.T) {
	r, err := NewResolver(Config{Allowed: []string{"https://"}})
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
	r := s.resolver(t, []string{"https://"}, &now, false)
	for _, iss := range []string{"", "https://user@example.com", "https://example.com?"} {
		if _, err := r.Keys(context.Background(), iss); !errors.Is(err, issuerkey.ErrIssuerNotSupported) {
			t.Errorf("Keys(%q) = %v, want ErrIssuerNotSupported", iss, err)
		}
	}
	if n := s.hits.Load(); n != 0 {
		t.Fatalf("server got %d requests, want 0", n)
	}
}

// An entry ending in "/" covers the iss under it except through a dot
// segment (RFC 3986 §6.2.2.3; reading \ and %2F as separators and ignoring
// ;-parameters are SDK policy); any other entry covers only itself.
func TestAllowed(t *testing.T) {
	routes := map[string]response{}
	for _, iss := range []string{"https://example.com", "https://example.com/tenant/1234"} {
		u, _ := MetadataURL(iss)
		routes[strings.TrimPrefix(u, "https://example.com")] = metadata(iss, twoKeys)
	}
	s := newMetaServer(t, routes)
	now := time.Unix(1_800_000_000, 0)
	r := s.resolver(t, []string{"https://example.com", "https://example.com/issuers", "https://example.com/tenant/"}, &now, false)
	for _, iss := range []string{
		"https://example.com/issuers-fake",
		"https://example.com/tenant/../x",
		"https://example.com/tenant/%2e%2E/x",
		"https://example.com/tenant/x%2F..%2Fy",
		`https://example.com/tenant/..\x`,
		"https://example.com/tenant/..;/x",
	} {
		if _, err := r.Keys(context.Background(), iss); !errors.Is(err, issuerkey.ErrIssuerNotSupported) {
			t.Errorf("Keys(%q) = %v, want ErrIssuerNotSupported", iss, err)
		}
	}
	if n := s.hits.Load(); n != 0 {
		t.Fatalf("refused iss: server got %d requests, want 0", n)
	}
	for _, iss := range []string{"https://example.com", "https://example.com/tenant/1234"} {
		if keys, err := r.Keys(context.Background(), iss); err != nil || len(keys) != 2 {
			t.Errorf("Keys(%q) = %d keys, %v; want 2 keys", iss, len(keys), err)
		}
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
	s := newMetaServer(t, map[string]response{
		"/.well-known/jwt-vc-issuer": {"application/json", "", `{"issuer":"https://example.com","jwks_uri":"http://example.com/jwks"}`},
		"/jwks":                      {"application/json", "", twoKeys},
	})
	now := time.Unix(1_800_000_000, 0)
	r := s.resolver(t, []string{"https://example.com"}, &now, false)
	if _, err := r.Keys(context.Background(), "https://example.com"); !errors.Is(err, issuerkey.ErrNoUsableKey) {
		t.Fatalf("err = %v, want ErrNoUsableKey", err)
	}
	if n := s.hits.Load(); n != 1 {
		t.Fatalf("hits = %d, want 1 (the metadata only)", n)
	}
}

// draft 19 §7.1: the default client refuses the loopback address the
// httptest server listens on.
func TestDefaultClientRefusesLoopback(t *testing.T) {
	s := newMetaServer(t, nil)
	r, err := NewResolver(Config{Allowed: []string{"https://"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Keys(context.Background(), s.srv.URL); !errors.Is(err, safehttp.ErrBlockedAddress) {
		t.Fatalf("err = %v, want safehttp.ErrBlockedAddress", err)
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
	if err == nil || errors.Is(err, issuerkey.ErrNoUsableKey) || errors.Is(err, issuerkey.ErrIssuerNotSupported) {
		t.Fatalf("err = %v, want a retrieval error", err)
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
