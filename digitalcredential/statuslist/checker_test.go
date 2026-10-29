package statuslist

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pilacorp/go-credential-sdk/digitalcredential/internal/safehttp"
	"github.com/pilacorp/go-credential-sdk/digitalcredential/issuerkey"
	"github.com/pilacorp/go-credential-sdk/jose"
	"github.com/pilacorp/go-credential-sdk/jose/jws"
)

// draft21Now is a time inside the validity of the draft 21 §5.1 example
// token (iat 1686920170, exp 2291720170).
var draft21Now = time.Unix(1686920170, 0).Add(time.Hour)

// keySet resolves each issuer to its published keys.
type keySet map[string][]issuerkey.Key

func (s keySet) Keys(_ context.Context, iss string) ([]issuerkey.Key, error) {
	return s[iss], nil
}

// listServer serves tokens[path] as application/statuslist+jwt. Its client
// reaches it for any host name, so the URIs of the draft (example.com, which
// the httptest certificate names) can be used as they are.
type listServer struct {
	tokens map[string]string
	hits   atomic.Int32
	srv    *httptest.Server
}

func newListServer(t *testing.T, tokens map[string]string) *listServer {
	t.Helper()
	s := &listServer{tokens: tokens}
	s.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		w.Header().Set("Content-Type", "application/statuslist+jwt")
		w.Write([]byte(s.tokens[r.URL.Path]))
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *listServer) checker(t *testing.T, issuers issuerkey.Resolver) *Checker {
	t.Helper()
	client := s.srv.Client()
	addr := s.srv.Listener.Addr().String()
	client.Transport.(*http.Transport).DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	c, err := NewChecker(issuers, WithHTTPClient(client))
	if err != nil {
		t.Fatal(err)
	}
	c.now = func() time.Time { return draft21Now }
	return c
}

func signClaims(t *testing.T, signer jws.Signer, pub *ecdsa.PublicKey, header jws.Header, claims map[string]any) string {
	t.Helper()
	payload, err := jose.EncodeJSON(claims)
	if err != nil {
		t.Fatal(err)
	}
	token, err := jws.Sign(signer, pub, header, payload)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// The bits=2 Status List of draft-ietf-oauth-status-list-21 §4.1/§4.2, signed
// by SignToken with the claims of the §5.1 example: Status returns each
// value as the draft lists it, 2 and 3 included (§7: the raw value).
func TestCheckerDraft21Section42Example(t *testing.T) {
	signer, pub := newP256Signer(t)
	l, err := FromBytes([]byte{0xc9, 0x44, 0xf9}, 2)
	if err != nil {
		t.Fatal(err)
	}
	const uri = "https://example.com/statuslists/1"
	token, err := SignToken(l, TokenClaims{
		Sub:      uri,
		IssuedAt: time.Unix(1686920170, 0),
		Expiry:   time.Unix(2291720170, 0),
		TTL:      43200 * time.Second,
	}, SigningKey{Signer: signer, Public: pub, KID: "12"})
	if err != nil {
		t.Fatal(err)
	}
	s := newListServer(t, map[string]string{"/statuslists/1": token})
	c := s.checker(t, keySet{"https://example.com": {{KID: "12", Key: pub}}})
	for i, want := range []uint8{1, 2, 0, 3, 0, 1, 0, 1, 1, 2, 3, 3} {
		got, err := c.Status(context.Background(), Ref{URI: uri, Index: i}, "https://example.com")
		if err != nil || got != want {
			t.Errorf("Status(%d) = %d, %v; want %d", i, got, err, want)
		}
	}
}

// Draft 21 §4.2: bits is a JSON integer, a value, so the RFC 8259 §6
// forms 1.0 and 10e-1 are the bits 1 and read like 1.
func TestCheckerReadsBitsByValue(t *testing.T) {
	signer, pub := newP256Signer(t)
	header := jws.Header{"typ": "statuslist+jwt", "kid": "k"}
	forms := []json.Number{"1", "1.0", "10e-1"}
	tokens := map[string]string{}
	for i, bits := range forms {
		tokens["/statuslists/"+strconv.Itoa(i)] = signClaims(t, signer, pub, header, map[string]any{
			"sub":         "https://example.com/statuslists/" + strconv.Itoa(i),
			"iat":         draft21Now.Add(-time.Hour).Unix(),
			"status_list": map[string]any{"bits": bits, "lst": "eNrbuRgAAhcBXQ"}, // §4.2: entry 0 is 1
		})
	}
	c := newListServer(t, tokens).checker(t, keySet{"https://example.com": {{KID: "k", Key: pub}}})
	for i, bits := range forms {
		ref := Ref{URI: "https://example.com/statuslists/" + strconv.Itoa(i), Index: 0}
		if got, err := c.Status(context.Background(), ref, "https://example.com"); err != nil || got != 1 {
			t.Errorf("bits %s: Status(0) = %d, %v; want 1", bits, got, err)
		}
	}
}

// Each token below fails a check of draft 21 §5.1 or §8.3, RFC 8725 §3.8,
// or the SDK's 16 MiB inflate cap, and must give an error, never a status
// value.
func TestCheckerRejects(t *testing.T) {
	signerA, pubA := newP256Signer(t)
	signerB, pubB := newP256Signer(t)
	issuers := keySet{"https://a.example": {{KID: "a", Key: pubA}}}
	header := jws.Header{"typ": "statuslist+jwt", "kid": "a"}
	claims := func(sub string, mutate func(map[string]any)) map[string]any {
		m := map[string]any{
			"sub":         sub,
			"iat":         draft21Now.Add(-time.Hour).Unix(),
			"status_list": map[string]any{"bits": 1, "lst": "eNrbuRgAAhcBXQ"}, // §4.2, 16 entries
		}
		if mutate != nil {
			mutate(m)
		}
		return m
	}
	const base = "https://example.com/statuslists/"
	tests := []struct {
		name  string
		token string
		index int
		oob   bool // ErrIndexOutOfBounds, and only this row
	}{
		{"lst inflates past 16 MiB", signClaims(t, signerA, pubA, header, claims(base+"0", func(m map[string]any) {
			lst := base64.RawURLEncoding.EncodeToString(deflate(t, make([]byte, 16<<20+1)))
			m["status_list"] = map[string]any{"bits": 1, "lst": lst}
		})), 0, false},
		{"index outside the list", signClaims(t, signerA, pubA, header, claims(base+"1", nil)), 16, true},
		{"sub is not the uri", signClaims(t, signerA, pubA, header, claims(base+"other", nil)), 0, false},
		// kid "a" names issuer A's key, but issuer B signed.
		{"signed by another issuer's key", signClaims(t, signerB, pubB, header, claims(base+"3", nil)), 0, false},
		// RFC 7519 §4.1.4: an old list replayed after its exp.
		{"expired", signClaims(t, signerA, pubA, header, claims(base+"4", func(m map[string]any) {
			m["exp"] = draft21Now.Add(-2 * time.Minute).Unix()
		})), 0, false},
		// RFC 8725 §3.11: another JWT of the issuer must not pass as a list.
		{"typ is not statuslist+jwt", signClaims(t, signerA, pubA, jws.Header{"typ": "JWT", "kid": "a"}, claims(base+"5", nil)), 0, false},
		// RFC 8725 §3.8: signed with issuer A's key, but iss names issuer B.
		{"iss naming another issuer", signClaims(t, signerA, pubA, header, claims(base+"6", func(m map[string]any) {
			m["iss"] = "https://b.example"
		})), 0, false},
		// RFC 7519 §4.1.3: the Checker is named in no aud, so any aud fails.
		{"aud present", signClaims(t, signerA, pubA, header, claims(base+"7", func(m map[string]any) {
			m["aud"] = []any{"https://verifier.example"}
		})), 0, false},
	}
	tokens := map[string]string{}
	for i, tt := range tests {
		tokens["/statuslists/"+strconv.Itoa(i)] = tt.token
	}
	s := newListServer(t, tokens)
	c := s.checker(t, issuers)
	for i, tt := range tests {
		ref := Ref{URI: base + strconv.Itoa(i), Index: tt.index}
		// None is a caller mistake: an index outside the list included
		// (draft 21 §8.3 step 6).
		got, err := c.Status(context.Background(), ref, "https://a.example")
		if err == nil || got != 0 || errors.Is(err, jose.ErrInvalidArgument) {
			t.Errorf("%s: Status = %d, %v; want an error that is not jose.ErrInvalidArgument", tt.name, got, err)
		}
		// Only §8.3 step 6 is a MUST reject; a caller tells it apart.
		if errors.Is(err, ErrIndexOutOfBounds) != tt.oob {
			t.Errorf("%s: errors.Is(%v, ErrIndexOutOfBounds) = %v, want %v", tt.name, err, !tt.oob, tt.oob)
		}
	}
}

// One uri, two issuers: a list verified with issuer A's key and cached must
// not answer for issuer B (the SDK's key rule, see NewChecker), and B's
// failure must not disturb A's entry.
func TestCheckerCacheIsolatesIssuers(t *testing.T) {
	signerA, pubA := newP256Signer(t)
	_, pubB := newP256Signer(t)
	const uri = "https://example.com/statuslists/1"
	token := signClaims(t, signerA, pubA, jws.Header{"typ": "statuslist+jwt", "kid": "k"}, map[string]any{
		"sub":         uri,
		"iat":         draft21Now.Add(-time.Hour).Unix(),
		"ttl":         3600,
		"status_list": map[string]any{"bits": 1, "lst": "eNrbuRgAAhcBXQ"}, // §4.2: entry 0 is 1
	})
	s := newListServer(t, map[string]string{"/statuslists/1": token})
	c := s.checker(t, keySet{
		"https://a.example": {{KID: "k", Key: pubA}},
		"https://b.example": {{KID: "k", Key: pubB}},
	})
	ref := Ref{URI: uri, Index: 0}
	if got, err := c.Status(context.Background(), ref, "https://a.example"); err != nil || got != 1 {
		t.Fatalf("issuer A: Status = %d, %v; want 1", got, err)
	}
	if got, err := c.Status(context.Background(), ref, "https://b.example"); err == nil {
		t.Errorf("issuer B: Status = %d, nil; want an error", got)
	}
	if got, err := c.Status(context.Background(), ref, "https://a.example"); err != nil || got != 1 {
		t.Errorf("issuer A again: Status = %d, %v; want 1", got, err)
	}
}

// A cached list answers only until its lifetime ends, ttl from the fetch
// (draft 21 §13.7) but never past exp (§5.1: exp ends the token's
// validity); a stale list must not keep answering after a revocation.
func TestCheckerCacheLifetime(t *testing.T) {
	signer, pub := newP256Signer(t)
	const uri = "https://example.com/statuslists/1"
	tests := []struct {
		name string
		exp  time.Duration // from draft21Now; 0: no exp
		last time.Duration // the cache still answers here
	}{
		{"ttl", 0, 59 * time.Second},
		{"exp before ttl ends", 30 * time.Second, 29 * time.Second},
	}
	for _, tt := range tests {
		claims := map[string]any{
			"sub":         uri,
			"iat":         draft21Now.Add(-time.Hour).Unix(),
			"ttl":         60,
			"status_list": map[string]any{"bits": 1, "lst": "eNrbuRgAAhcBXQ"},
		}
		if tt.exp != 0 {
			claims["exp"] = draft21Now.Add(tt.exp).Unix()
		}
		token := signClaims(t, signer, pub, jws.Header{"typ": "statuslist+jwt", "kid": "k"}, claims)
		s := newListServer(t, map[string]string{"/statuslists/1": token})
		c := s.checker(t, keySet{"https://a.example": {{KID: "k", Key: pub}}})
		now := draft21Now
		c.now = func() time.Time { return now }
		for _, at := range []time.Duration{0, tt.last, tt.last + 2*time.Second} {
			now = draft21Now.Add(at)
			if _, err := c.Status(context.Background(), Ref{URI: uri}, "https://a.example"); err != nil {
				t.Fatalf("%s: Status at +%v: %v", tt.name, at, err)
			}
		}
		if n := s.hits.Load(); n != 2 {
			t.Errorf("%s: server got %d requests, want 2 (cached until +%v, fetched again after)", tt.name, n, tt.last)
		}
	}
}

// An issuer may grow a list (draft 21 §13.4). An index past a cached copy
// is checked against the token fetched again, and only an index past that
// one is ErrIndexOutOfBounds.
func TestCheckerRefetchesGrownList(t *testing.T) {
	signer, pub := newP256Signer(t)
	const uri, iss = "https://example.com/statuslists/g", "https://a.example"
	sign := func(entries int, iat time.Time) string {
		l, err := New(entries, 1)
		if err != nil {
			t.Fatal(err)
		}
		if entries > 12 {
			if err := l.Set(12, 1); err != nil {
				t.Fatal(err)
			}
		}
		token, err := SignToken(l, TokenClaims{Sub: uri, IssuedAt: iat, TTL: time.Hour}, SigningKey{Signer: signer, Public: pub, KID: "k"})
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	s := newListServer(t, map[string]string{"/statuslists/g": sign(8, draft21Now.Add(-time.Hour))})
	c := s.checker(t, keySet{iss: {{KID: "k", Key: pub}}})
	ctx := context.Background()
	if _, err := c.Status(ctx, Ref{URI: uri, Index: 3}, iss); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Status(ctx, Ref{URI: uri, Index: 12}, iss); !errors.Is(err, ErrIndexOutOfBounds) {
		t.Fatalf("idx 12 of 8 entries, fetched again: err = %v, want ErrIndexOutOfBounds", err)
	}
	if n := s.hits.Load(); n != 2 {
		t.Fatalf("server got %d requests, want 2 (the index past the cached list fetches again)", n)
	}
	s.tokens["/statuslists/g"] = sign(16, draft21Now.Add(-time.Minute))
	if v, err := c.Status(ctx, Ref{URI: uri, Index: 12}, iss); err != nil || v != 1 {
		t.Fatalf("idx 12 after the list grew to 16: Status = %d, %v; want 1", v, err)
	}
	// The grown list replaced the cached one.
	if v, err := c.Status(ctx, Ref{URI: uri, Index: 12}, iss); err != nil || v != 1 || s.hits.Load() != 3 {
		t.Fatalf("idx 12 again: Status = %d, %v after %d requests; want 1 from the cache after 3", v, err, s.hits.Load())
	}
}

// The cache holds at most maxCacheBytes of lists. Once full it caches no new
// list while every entry is live, and drops expired entries to make room.
func TestCheckerCacheBudget(t *testing.T) {
	c, err := NewChecker(keySet{})
	if err != nil {
		t.Fatal(err)
	}
	now := draft21Now
	c.now = func() time.Time { return now }
	const iss = "https://a.example"
	store := func(n int, expires time.Time) bool {
		l, err := New(1<<23, 1) // 1 MiB
		if err != nil {
			t.Fatal(err)
		}
		key := cacheKey{iss: iss, uri: "https://a.example/l/" + strconv.Itoa(n)}
		c.store(key, l, now, expires)
		return c.cached(key) != nil
	}
	// 32 lists of 1 MiB and their keys exceed 32 MiB: the 32nd is refused.
	for n := range 31 {
		if !store(n, draft21Now.Add(time.Hour)) {
			t.Fatalf("list %d of 1 MiB not cached", n)
		}
	}
	if store(31, draft21Now.Add(2*time.Hour)) {
		t.Fatal("cached a 32nd list of 1 MiB, past the 32 MiB budget")
	}
	now = draft21Now.Add(time.Hour)
	if !store(32, draft21Now.Add(2*time.Hour)) {
		t.Fatal("the cached lists expired, but a new list was not cached")
	}
}

// Two fetches of one list can finish out of order. A cached list must not
// be replaced by one from an older token (draft 21 §5.1: iat is when the
// token was issued), or a revocation already seen would be undone.
func TestCheckerKeepsNewerList(t *testing.T) {
	c, err := NewChecker(keySet{})
	if err != nil {
		t.Fatal(err)
	}
	c.now = func() time.Time { return draft21Now }
	revoked, err := FromBytes([]byte{0x01}, 1)
	if err != nil {
		t.Fatal(err)
	}
	valid, err := FromBytes([]byte{0x00}, 1)
	if err != nil {
		t.Fatal(err)
	}
	key := cacheKey{iss: "https://a.example", uri: "https://example.com/statuslists/1"}
	expires := draft21Now.Add(time.Minute)
	c.store(key, revoked, draft21Now.Add(-time.Second), expires)
	c.store(key, valid, draft21Now.Add(-time.Hour), expires)
	if got, err := c.cached(key).Get(0); err != nil || got != 1 {
		t.Errorf("cached entry 0 = %d, %v; want 1 from the newer token", got, err)
	}
}

// A token valid when its claims were checked may expire while its list
// waits for a decode slot; it must then be refused (RFC 7519 §4.1.4), not
// answered once. The clock jumps past exp + skew once a slot is held.
func TestCheckerRefusesTokenExpiredWhileDecoding(t *testing.T) {
	signer, pub := newP256Signer(t)
	const uri = "https://example.com/statuslists/1"
	token := signClaims(t, signer, pub, jws.Header{"typ": "statuslist+jwt", "kid": "k"}, map[string]any{
		"sub":         uri,
		"iat":         draft21Now.Add(-time.Hour).Unix(),
		"exp":         draft21Now.Add(-clockSkew + time.Second).Unix(),
		"status_list": map[string]any{"bits": 1, "lst": "eNrbuRgAAhcBXQ"},
	})
	s := newListServer(t, map[string]string{"/statuslists/1": token})
	c := s.checker(t, keySet{"https://a.example": {{KID: "k", Key: pub}}})
	late := false
	c.now = func() time.Time {
		late = late || len(c.slots) > 0
		if late {
			return draft21Now.Add(time.Minute)
		}
		return draft21Now
	}
	if got, err := c.Status(context.Background(), Ref{URI: uri}, "https://a.example"); err == nil {
		t.Errorf("Status = %d, nil; want an error for a token expired before its decode ended", got)
	}
}

// The default client refuses a status list uri resolving to a private
// address (draft-ietf-oauth-sd-jwt-vc-19 §7.1): the httptest server listens
// on 127.0.0.1 and must get no request.
func TestCheckerRefusesPrivateAddress(t *testing.T) {
	s := newListServer(t, map[string]string{})
	c, err := NewChecker(keySet{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Status(context.Background(), Ref{URI: s.srv.URL + "/statuslists/1"}, "https://a.example")
	if !errors.Is(err, safehttp.ErrBlockedAddress) {
		t.Fatalf("Status = %v, want safehttp.ErrBlockedAddress", err)
	}
	if n := s.hits.Load(); n != 0 {
		t.Fatalf("server got %d requests, want 0", n)
	}
}

// draft-ietf-oauth-status-list-21 §6.2 leaves the scheme of uri to the
// Relying Party. By default the Checker fetches https only, on the uri and on
// every redirect, and an http uri is not jose.ErrInvalidArgument: it comes
// from the credential. WithInsecureHTTP fetches http, redirects included.
func TestCheckerHTTP(t *testing.T) {
	signer, pub := newP256Signer(t)
	l, err := New(16, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Set(3, 1); err != nil {
		t.Fatal(err)
	}
	var token string
	var plainHits atomic.Int32
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		plainHits.Add(1)
		if r.URL.Path == "/statuslists/1" {
			http.Redirect(w, r, "/lists/1", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "application/statuslist+jwt")
		w.Write([]byte(token))
	}))
	t.Cleanup(plain.Close)
	uri := plain.URL + "/statuslists/1"
	if token, err = SignToken(l, TokenClaims{Sub: uri, IssuedAt: time.Unix(1686920170, 0)}, SigningKey{Signer: signer, Public: pub}); err != nil {
		t.Fatal(err)
	}
	issuers := keySet{"https://a.example": {{Key: pub}}}
	ref := Ref{URI: uri, Index: 3}

	c, err := NewChecker(issuers, WithHTTPClient(plain.Client()))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := c.Status(context.Background(), ref, "https://a.example"); err == nil || errors.Is(err, jose.ErrInvalidArgument) {
		t.Errorf("default, http uri: Status = %d, %v; want an error other than jose.ErrInvalidArgument", got, err)
	}
	if n := plainHits.Load(); n != 0 {
		t.Errorf("default, http uri: server got %d requests, want 0", n)
	}
	// The refusal leaves the uri out: a credential's uri may carry a password
	// in its userinfo (RFC 3986 §7.5) or a token in its query.
	for _, uri := range []string{"http://alice:SYNTHETIC_PASSWORD@status.example/list", "http://status.example/list?token=SYNTHETIC_QUERY_SECRET"} {
		_, err := c.Status(context.Background(), Ref{URI: uri}, "https://a.example")
		if err == nil || errors.Is(err, jose.ErrInvalidArgument) || strings.Contains(err.Error(), "SYNTHETIC") {
			t.Errorf("default, %s: Status error %v; want one other than jose.ErrInvalidArgument, without the uri", uri, err)
		}
	}

	downgrade := httptest.NewTLSServer(http.RedirectHandler(uri, http.StatusFound))
	t.Cleanup(downgrade.Close)
	if c, err = NewChecker(issuers, WithHTTPClient(downgrade.Client())); err != nil {
		t.Fatal(err)
	}
	if got, err := c.Status(context.Background(), Ref{URI: downgrade.URL + "/statuslists/1"}, "https://a.example"); err == nil {
		t.Errorf("default, redirect to http: Status = %d, nil; want an error", got)
	}
	if n := plainHits.Load(); n != 0 {
		t.Errorf("default, redirect to http: http server got %d requests, want 0", n)
	}

	if c, err = NewChecker(issuers, WithHTTPClient(plain.Client()), WithInsecureHTTP()); err != nil {
		t.Fatal(err)
	}
	c.now = func() time.Time { return draft21Now }
	if got, err := c.Status(context.Background(), ref, "https://a.example"); err != nil || got != 1 {
		t.Errorf("WithInsecureHTTP: Status = %d, %v; want 1", got, err)
	}
	if n := plainHits.Load(); n != 2 {
		t.Errorf("WithInsecureHTTP: server got %d requests, want 2 (a redirect, then the token)", n)
	}
}
