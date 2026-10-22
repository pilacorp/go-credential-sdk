package statuslist

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	decredecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/pilacorp/go-credential-sdk/digitalcredential/internal/safehttp"
	"github.com/pilacorp/go-credential-sdk/jose"
)

// p256Signer signs in memory and returns r||s.
type p256Signer struct{ priv *ecdsa.PrivateKey }

func newP256(t testing.TB) (*p256Signer, *ecdsa.PublicKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &p256Signer{priv}, &priv.PublicKey
}

func (s *p256Signer) Sign(digest []byte) ([]byte, error) {
	r, sv, err := ecdsa.Sign(rand.Reader, s.priv, digest)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	sv.FillBytes(out[32:])
	return out, nil
}

// secpVaultSigner signs with secp256k1 and answers r||s||v (65 bytes), as a
// Vault callback does.
type secpVaultSigner struct{ priv *secp256k1.PrivateKey }

func newSecpVault(t testing.TB) (*secpVaultSigner, *ecdsa.PublicKey) {
	t.Helper()
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return &secpVaultSigner{priv}, priv.PubKey().ToECDSA()
}

func (s *secpVaultSigner) Sign(digest []byte) ([]byte, error) {
	sig := decredecdsa.Sign(s.priv, digest)
	r, sv := sig.R(), sig.S()
	rb, sb := r.Bytes(), sv.Bytes()
	return append(append(rb[:], sb[:]...), 1), nil
}

// resolver maps iss to a key and records every call.
type resolver struct {
	mu     sync.Mutex
	keys   map[string]*ecdsa.PublicKey
	calls  []string // "iss kid"
	err    error
	nilKey bool // answer (nil, nil)
}

func (r *resolver) IssuerKey(_ context.Context, iss string, h jose.Header) (*ecdsa.PublicKey, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, iss+" "+h.Kid())
	if r.err != nil {
		return nil, r.err
	}
	if r.nilKey {
		return nil, nil
	}
	k, ok := r.keys[iss]
	if !ok {
		return nil, errors.New("unknown issuer")
	}
	return k, nil
}

// server serves one status list token over TLS and counts the fetches.
type server struct {
	*httptest.Server
	mu          sync.Mutex
	token       string
	contentType string
	status      int
	fetches     int
}

func newServer(t testing.TB) *server {
	t.Helper()
	s := &server{contentType: MediaType, status: http.StatusOK}
	s.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.fetches++
		if r.Header.Get("Accept") != MediaType {
			http.Error(w, "Accept must be "+MediaType, http.StatusNotAcceptable)
			return
		}
		w.Header().Set("Content-Type", s.contentType)
		w.WriteHeader(s.status)
		_, _ = w.Write([]byte(s.token))
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *server) set(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.token = token
}

func (s *server) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fetches
}

// uri is the status list URI on this server; it is also the token's sub.
func (s *server) uri() string { return s.URL + "/statuslists/1" }

// testClient is the SSRF-checking client, trusting the test certificate and
// letting exactly the given servers' addresses through.
func testClient(t testing.TB, srvs ...*httptest.Server) *http.Client {
	t.Helper()
	pool := x509.NewCertPool()
	var allow []netip.AddrPort
	for _, s := range srvs {
		pool.AddCert(s.Certificate())
		allow = append(allow, netip.MustParseAddrPort(s.Listener.Addr().String()))
	}
	return safehttp.NewClient(safehttp.Options{TLSConfig: &tls.Config{RootCAs: pool}, AllowAddrs: allow})
}

func mustList(t testing.TB, size, bits int, set map[int]byte) *List {
	t.Helper()
	l, err := New(size, bits)
	if err != nil {
		t.Fatal(err)
	}
	for i, v := range set {
		if err := l.Set(i, v); err != nil {
			t.Fatal(err)
		}
	}
	return l
}

// signRaw signs header and payload as given, for tokens SignToken would refuse
// to build.
func signRaw(t testing.TB, s jose.Signer, alg string, header map[string]any, payload string) string {
	t.Helper()
	tok, err := jose.Sign(s, alg, header, []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func wantErr(t testing.TB, err, target error) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("error %v, want %v", err, target)
	}
}
