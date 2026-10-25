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
	_, _, err := Get(context.Background(), NewClient(), s.URL, "application/json", limits)
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

	if _, _, err := Get(context.Background(), s.Client(), s.URL+"/downgrade", "application/json", limits); err == nil {
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
	if _, _, err := Get(context.Background(), c, s.URL+"/nohost", "application/json", limits); err == nil {
		t.Error("redirect to https without a host: err = nil")
	}
	if targetHits.Load() != 0 {
		t.Errorf("local server got %d requests, want 0", targetHits.Load())
	}

	if _, _, err := Get(context.Background(), s.Client(), s.URL+"/hop/0", "application/json", limits); err == nil {
		t.Error("too many redirects: err = nil")
	}
	if got, want := hops.Load(), int32(limits.MaxRedirects+1); got != want {
		t.Errorf("server got %d requests, want %d", got, want)
	}
}

func TestGetRefusesBodyOverCap(t *testing.T) {
	var hits atomic.Int32
	s := jsonServer(t, true, strings.Repeat("a", int(limits.MaxBytes)+1), &hits)
	if _, _, err := Get(context.Background(), s.Client(), s.URL, "application/json", limits); err == nil {
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
	_, _, err := Get(context.Background(), s.Client(), s.URL, "application/json", l)
	if err == nil || errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "body over") {
		t.Fatalf("err = %v, want the byte cap error before the timeout", err)
	}
}

// draft-ietf-oauth-sd-jwt-vc-19 §3 (HTTPS only), RFC 9110 §4.2.2 (an https
// URI with an empty host is invalid) and §4.2.4 (a recipient SHOULD treat
// userinfo as an error): refused before any request, whatever the client.
func TestGetRefusesURL(t *testing.T) {
	var hits atomic.Int32
	plain := jsonServer(t, false, "{}", &hits)
	s := jsonServer(t, true, "{}", &hits)
	c := s.Client()
	// Name the test certificate, so the empty host is refused by Get rather
	// than by the TLS handshake.
	c.Transport.(*http.Transport).TLSClientConfig.ServerName = "127.0.0.1"
	_, port, _ := net.SplitHostPort(s.Listener.Addr().String())
	for _, u := range []string{plain.URL, "https://:" + port + "/", "https://user:pass@127.0.0.1:" + port + "/"} {
		if _, _, err := Get(context.Background(), c, u, "application/json", limits); err == nil {
			t.Errorf("Get(%s): err = nil", u)
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
	if _, _, err := Get(context.Background(), s.Client(), s.URL, "application/json", l); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want context.DeadlineExceeded", err)
	}
}
