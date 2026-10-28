package safehttp

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var limits = Limits{Timeout: 5 * time.Second, MaxRedirects: 3, MaxBytes: 1024}

func jsonServer(t *testing.T, tls bool, body string, hits *atomic.Int32) *httptest.Server {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, body)
	})
	s := httptest.NewUnstartedServer(h)
	if tls {
		s.StartTLS()
	} else {
		s.Start()
	}
	t.Cleanup(s.Close)
	return s
}

// The httptest server listens on 127.0.0.1, so the dialer of NewClient must
// refuse it before any request reaches it.
func TestNewClientRefusesBlockedAddress(t *testing.T) {
	var hits atomic.Int32
	s := jsonServer(t, true, "{}", &hits)
	_, _, err := Get(context.Background(), NewClient(), s.URL, []string{"application/json"}, limits)
	if !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("err = %v, want ErrBlockedAddress", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("server got %d requests, want 0", hits.Load())
	}
}

func TestGetRefusesRedirect(t *testing.T) {
	var plainHits, targetHits atomic.Int32
	plain := jsonServer(t, false, "{}", &plainHits)
	target := jsonServer(t, true, "{}", &targetHits)
	_, targetPort, _ := net.SplitHostPort(target.Listener.Addr().String())

	var hops atomic.Int32
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/downgrade":
			http.Redirect(w, r, plain.URL, http.StatusFound)
			return
		case "/nohost":
			http.Redirect(w, r, "https://:"+targetPort+"/", http.StatusFound)
			return
		}
		// /hop/n redirects to /hop/n+1; the request after the last allowed
		// redirect must never arrive.
		hops.Add(1)
		var n int
		fmt.Sscanf(strings.TrimPrefix(r.URL.Path, "/hop/"), "%d", &n)
		http.Redirect(w, r, fmt.Sprintf("/hop/%d", n+1), http.StatusFound)
	}))
	t.Cleanup(s.Close)

	if _, _, err := Get(context.Background(), s.Client(), s.URL+"/downgrade", []string{"application/json"}, limits); err == nil {
		t.Error("redirect to http: err = nil")
	}
	if plainHits.Load() != 0 {
		t.Errorf("http server got %d requests, want 0", plainHits.Load())
	}

	// RFC 9110 §4.2.2: an https URI with an empty host is invalid; a client
	// dialing ":port" reaches the local host. Naming the test certificate makes
	// Get, not the TLS handshake, the check that refuses it.
	c := s.Client()
	c.Transport.(*http.Transport).TLSClientConfig.ServerName = "127.0.0.1"
	if _, _, err := Get(context.Background(), c, s.URL+"/nohost", []string{"application/json"}, limits); err == nil {
		t.Error("redirect to https without a host: err = nil")
	}
	if targetHits.Load() != 0 {
		t.Errorf("local server got %d requests, want 0", targetHits.Load())
	}

	if _, _, err := Get(context.Background(), s.Client(), s.URL+"/hop/0", []string{"application/json"}, limits); err == nil {
		t.Error("too many redirects: err = nil")
	}
	if got, want := hops.Load(), int32(limits.MaxRedirects+1); got != want {
		t.Errorf("server got %d requests, want %d", got, want)
	}
}

// A fetch error leaves out the URL: a credential's uri may carry a token in
// its query, and a refused redirect's Location a password in its userinfo
// (RFC 3986 §7.5). The cause is kept.
func TestGetErrorOmitsURL(t *testing.T) {
	redirect := httptest.NewTLSServer(http.RedirectHandler("https://alice:SYNTHETIC_PW@status.example/x?token=SYNTHETIC_Q", http.StatusFound))
	t.Cleanup(redirect.Close)
	_, _, err := Get(context.Background(), redirect.Client(), redirect.URL, []string{"application/json"}, limits)
	if err == nil || strings.Contains(err.Error(), "SYNTHETIC") || !strings.Contains(err.Error(), "redirect to a URL that is not https") {
		t.Errorf("refused redirect: err = %v; want the refusal without the URL", err)
	}

	// net/http parses a Location before CheckRedirect sees it and quotes the
	// raw header when the parse fails.
	var hops atomic.Int32
	malformed := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hops.Add(1)
		w.Header().Set("Location", "https://alice:SYNTHETIC_PASSWORD@status.example/%zz?token=SYNTHETIC_QUERY_SECRET")
		w.WriteHeader(http.StatusFound)
	}))
	t.Cleanup(malformed.Close)
	_, _, err = Get(context.Background(), malformed.Client(), malformed.URL, []string{"application/json"}, limits)
	if err == nil || strings.Contains(err.Error(), "SYNTHETIC") || hops.Load() != 1 {
		t.Errorf("malformed Location: err = %v after %d requests; want an error without the URL after 1", err, hops.Load())
	}

	// The test server listens on 127.0.0.1, which the dialer of NewClient refuses.
	var hits atomic.Int32
	s := jsonServer(t, true, "{}", &hits)
	_, _, err = Get(context.Background(), NewClient(), s.URL+"/?token=SYNTHETIC_Q", []string{"application/json"}, limits)
	if !errors.Is(err, ErrBlockedAddress) || strings.Contains(err.Error(), "SYNTHETIC") {
		t.Errorf("blocked address: err = %v; want ErrBlockedAddress without the URL", err)
	}
}

// A JWK Set may be served as application/jwk-set+json (RFC 7517 §8.5) or as
// application/json, so a caller passes both: either is accepted, any other is
// refused, and both are sent as Accept.
func TestGetMediaTypes(t *testing.T) {
	var accept atomic.Value
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accept.Store(r.Header.Get("Accept"))
		w.Header().Set("Content-Type", strings.TrimPrefix(r.URL.Path, "/"))
		fmt.Fprint(w, "{}")
	}))
	t.Cleanup(s.Close)
	types := []string{"application/jwk-set+json", "application/json"}
	for _, ct := range []string{"application/jwk-set+json", "application/JSON"} {
		if _, _, err := Get(context.Background(), s.Client(), s.URL+"/"+ct, types, limits); err != nil {
			t.Errorf("Content-Type %s: err = %v", ct, err)
		}
	}
	if got := accept.Load(); got != "application/jwk-set+json, application/json" {
		t.Errorf("Accept = %q", got)
	}
	_, _, err := Get(context.Background(), s.Client(), s.URL+"/text/html", types, limits)
	if err == nil || err.Error() != "safehttp: content type is not application/jwk-set+json or application/json" {
		t.Errorf("Content-Type text/html: err = %v", err)
	}
}

func TestGetRefusesBodyOverCap(t *testing.T) {
	var hits atomic.Int32
	s := jsonServer(t, true, strings.Repeat("a", int(limits.MaxBytes)+1), &hits)
	if _, _, err := Get(context.Background(), s.Client(), s.URL, []string{"application/json"}, limits); err == nil {
		t.Fatal("err = nil")
	}
}

// A server may send gzip although Get asks for identity. Empty deflate blocks
// decompress to nothing, so with transparent decompression the cap is never
// reached and only l.Timeout ends the read; counting the bytes sent ends it.
func TestGetRefusesCompressedBodyOverCap(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		for r.Context().Err() == nil {
			// Each Flush writes one empty stored block, 5 bytes on the wire.
			if err := gz.Flush(); err != nil {
				return
			}
			w.(http.Flusher).Flush()
		}
	}))
	t.Cleanup(s.Close)
	l := limits
	l.MaxBytes = 64
	_, _, err := Get(context.Background(), s.Client(), s.URL, []string{"application/json"}, l)
	if err == nil || errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "body over") {
		t.Fatalf("err = %v, want the byte cap error before the timeout", err)
	}
}

// draft-ietf-oauth-sd-jwt-vc-19 §3 (HTTPS only), RFC 9110 §4.2.2 (an https
// URI with an empty host is invalid) and §4.2.4 (a recipient SHOULD treat
// userinfo as an error): refused before any request, whatever the client.
// AllowHTTP relaxes the scheme only.
func TestGetRefusesURL(t *testing.T) {
	var hits atomic.Int32
	plain := jsonServer(t, false, "{}", &hits)
	s := jsonServer(t, true, "{}", &hits)
	c := s.Client()
	// Name the test certificate, so the empty host is refused by Get rather
	// than by the TLS handshake.
	c.Transport.(*http.Transport).TLSClientConfig.ServerName = "127.0.0.1"
	_, port, _ := net.SplitHostPort(s.Listener.Addr().String())
	_, plainPort, _ := net.SplitHostPort(plain.Listener.Addr().String())
	for _, u := range []string{plain.URL, "https://:" + port + "/", "https://user:pass@127.0.0.1:" + port + "/"} {
		if _, _, err := Get(context.Background(), c, u, []string{"application/json"}, limits); err == nil {
			t.Errorf("Get(%s): err = nil", u)
		}
	}
	httpLimits := limits
	httpLimits.AllowHTTP = true
	for _, u := range []string{"http://:" + plainPort + "/", "http://user:pass@127.0.0.1:" + plainPort + "/"} {
		if _, _, err := Get(context.Background(), plain.Client(), u, []string{"application/json"}, httpLimits); err == nil {
			t.Errorf("Get(%s) with AllowHTTP: err = nil", u)
		}
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("servers got %d requests, want 0", n)
	}
}

// draft-ietf-oauth-sd-jwt-vc-19 §3: each retrieval is time-bound, the body
// included.
func TestGetTimesOutStalledBody(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, "{")
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
			fmt.Fprint(w, "}")
		}
	}))
	t.Cleanup(s.Close)
	l := limits
	l.Timeout = 200 * time.Millisecond
	if _, _, err := Get(context.Background(), s.Client(), s.URL, []string{"application/json"}, l); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want context.DeadlineExceeded", err)
	}
}
