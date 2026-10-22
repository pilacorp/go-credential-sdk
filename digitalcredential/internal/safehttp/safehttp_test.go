package safehttp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

func TestBlocked(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "127.255.255.254", "::1", // loopback
		"10.0.0.5", "172.16.0.1", "172.31.255.255", "192.168.1.1", "fc00::1", "fd12:3456::1", // private
		"169.254.169.254", "169.254.0.1", "fe80::1", "fe80::1%en0", // link-local
		"0.0.0.0", "::", // unspecified
		"224.0.0.1", "239.255.255.250", "ff02::1", "ff01::1", "ff0e::1", // multicast
		"::ffff:127.0.0.1", "::ffff:10.0.0.5", "::ffff:169.254.169.254", "::ffff:0.0.0.0", // IPv4-mapped
		"64:ff9b::a9fe:a9fe", "64:ff9b::7f00:1", // NAT64 to 169.254.169.254 and 127.0.0.1
		"0.1.2.3", "100.64.0.1", "100.100.100.200", "100.127.255.255", "255.255.255.255",
	}
	for _, s := range blocked {
		if !Blocked(netip.MustParseAddr(s)) {
			t.Errorf("Blocked(%s) = false, want true", s)
		}
	}
	if !Blocked(netip.Addr{}) {
		t.Error("the zero Addr must be blocked")
	}
	allowed := []string{
		"8.8.8.8", "1.1.1.1", "172.15.255.255", "172.32.0.1", "192.169.0.1", "169.253.255.255", "169.255.0.1",
		"100.63.255.255", "100.128.0.1", "11.0.0.1", "223.255.255.255",
		"2001:4860:4860::8888", "::ffff:8.8.8.8", "64:ff9b::808:808", "fbff::1", "fe00::1",
	}
	for _, s := range allowed {
		if Blocked(netip.MustParseAddr(s)) {
			t.Errorf("Blocked(%s) = true, want false", s)
		}
	}
}

func TestControl(t *testing.T) {
	strict := control(false, []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:8443")})
	for _, addr := range []string{"10.0.0.5:443", "127.0.0.1:443", "[::ffff:10.0.0.5]:443", "[fe80::1%en0]:443", "169.254.169.254:80", "not an address", "example.com:443"} {
		if err := strict("tcp", addr, nil); !errors.Is(err, ErrBlockedAddress) {
			t.Errorf("control(%q) = %v, want ErrBlockedAddress", addr, err)
		}
	}
	for _, addr := range []string{"8.8.8.8:443", "[2001:4860:4860::8888]:443", "127.0.0.1:8443"} {
		if err := strict("tcp", addr, nil); err != nil {
			t.Errorf("control(%q) = %v, want nil", addr, err)
		}
	}
	open := control(true, nil)
	if err := open("tcp", "10.0.0.5:443", nil); err != nil {
		t.Errorf("AllowPrivateNetworks: %v", err)
	}
	if err := open("tcp", "garbage", nil); !errors.Is(err, ErrBlockedAddress) {
		t.Errorf("an unparsable address must be refused even with AllowPrivateNetworks, got %v", err)
	}
}

// tlsServer starts an httptest TLS server and returns it with a client that
// trusts it and lets exactly its address through the dialer check.
func tlsServer(t *testing.T, h http.Handler, o Options) (*httptest.Server, *http.Client) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	o.TLSConfig = &tls.Config{RootCAs: pool}
	o.AllowAddrs = append(o.AllowAddrs, netip.MustParseAddrPort(srv.Listener.Addr().String()))
	return srv, NewClient(o)
}

func get(c *http.Client, url string, maxBytes int64) ([]byte, error) {
	body, _, err := Get(context.Background(), c, url, "application/statuslist+jwt", maxBytes)
	return body, err
}

func TestClientRefusesInternalAddresses(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/statuslist+jwt")
		_, _ = w.Write([]byte("token"))
	}))
	defer srv.Close()
	port := strconv.Itoa(int(netip.MustParseAddrPort(srv.Listener.Addr().String()).Port()))

	c := NewClient(Options{})
	for _, url := range []string{
		srv.URL,                              // 127.0.0.1
		"https://localhost:" + port + "/",    // a name resolving to loopback
		"https://[::ffff:127.0.0.1]:" + port, // IPv4-mapped loopback
		"https://10.0.0.5/statuslists/1",     // refused before any packet is sent
		"https://169.254.169.254/latest/meta-data",
		"https://[::ffff:10.0.0.5]/",
	} {
		_, err := get(c, url, 1024)
		if !errors.Is(err, ErrBlockedAddress) {
			t.Errorf("GET %s: %v, want ErrBlockedAddress", url, err)
		}
	}

	// AllowPrivateNetworks turns the check off: the dial now succeeds and
	// fails later on the untrusted test certificate.
	_, err := get(NewClient(Options{AllowPrivateNetworks: true}), srv.URL, 1024)
	var unknownAuthority x509.UnknownAuthorityError
	if errors.Is(err, ErrBlockedAddress) || !errors.As(err, &unknownAuthority) {
		t.Errorf("AllowPrivateNetworks: %v, want a certificate error", err)
	}
}

func TestClientIgnoresProxyEnvironment(t *testing.T) {
	tr := NewClient(Options{}).Transport.(*http.Transport)
	if tr.Proxy != nil {
		t.Fatal("a proxy would make the dialer check the proxy's address instead of the target's")
	}
}

func TestRedirects(t *testing.T) {
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/statuslist+jwt")
		_, _ = w.Write([]byte("from another local port"))
	}))
	defer other.Close()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/hops/"):
			n, _ := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/hops/"))
			if n > 0 {
				http.Redirect(w, r, fmt.Sprintf("/hops/%d", n-1), http.StatusFound)
				return
			}
		case r.URL.Path == "/to-http":
			http.Redirect(w, r, "http://"+r.Host+"/hops/0", http.StatusFound)
			return
		case r.URL.Path == "/to-private":
			http.Redirect(w, r, "https://10.0.0.5/list", http.StatusFound)
			return
		case r.URL.Path == "/to-other-port":
			http.Redirect(w, r, other.URL+"/list", http.StatusFound)
			return
		}
		if r.Header.Get("Accept") != "application/statuslist+jwt" {
			http.Error(w, "Accept lost on redirect", http.StatusNotAcceptable)
			return
		}
		w.Header().Set("Content-Type", "application/statuslist+jwt")
		_, _ = w.Write([]byte("ok"))
	})

	srv, c := tlsServer(t, handler, Options{})
	if _, err := get(c, srv.URL+"/hops/3", 100); err != nil {
		t.Errorf("3 redirects with the default limit: %v", err)
	}
	if _, err := get(c, srv.URL+"/hops/4", 100); !errors.Is(err, ErrRedirect) {
		t.Errorf("4 redirects: %v, want ErrRedirect", err)
	}
	if _, err := get(c, srv.URL+"/to-http", 100); !errors.Is(err, ErrRedirect) {
		t.Errorf("redirect to http: %v, want ErrRedirect", err)
	}
	if _, err := get(c, srv.URL+"/to-private", 100); !errors.Is(err, ErrBlockedAddress) {
		t.Errorf("redirect to 10.0.0.5: %v, want ErrBlockedAddress", err)
	}
	if _, err := get(c, srv.URL+"/to-other-port", 100); !errors.Is(err, ErrBlockedAddress) {
		t.Errorf("redirect to another loopback port: %v, want ErrBlockedAddress", err)
	}

	srv1, c1 := tlsServer(t, handler, Options{MaxRedirects: 1})
	if _, err := get(c1, srv1.URL+"/hops/1", 100); err != nil {
		t.Errorf("MaxRedirects 1, 1 redirect: %v", err)
	}
	if _, err := get(c1, srv1.URL+"/hops/2", 100); !errors.Is(err, ErrRedirect) {
		t.Errorf("MaxRedirects 1, 2 redirects: %v, want ErrRedirect", err)
	}
	srv0, c0 := tlsServer(t, handler, Options{MaxRedirects: -1})
	if _, err := get(c0, srv0.URL+"/hops/1", 100); !errors.Is(err, ErrRedirect) {
		t.Errorf("negative MaxRedirects, 1 redirect: %v, want ErrRedirect", err)
	}
}

func TestGet(t *testing.T) {
	var status int
	var contentType, body string
	srv, c := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != "application/statuslist+jwt" {
			http.Error(w, "wrong Accept", http.StatusNotAcceptable)
			return
		}
		if contentType != "" {
			w.Header().Set("Content-Type", contentType)
		} else {
			w.Header()["Content-Type"] = nil
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}), Options{})

	for _, tc := range []struct {
		name, contentType, body string
		status                  int
		max                     int64
		want                    error
	}{
		{"ok", "application/statuslist+jwt", "abcd", 200, 4, nil},
		{"media type parameters and case", "Application/StatusList+JWT; charset=utf-8", "abcd", 200, 4, nil},
		{"body over the limit", "application/statuslist+jwt", "abcde", 200, 4, ErrTooLarge},
		{"status 404", "application/statuslist+jwt", "abcd", 404, 4, ErrResponse},
		{"status 204", "application/statuslist+jwt", "", 204, 4, ErrResponse},
		{"wrong Content-Type", "application/json", "abcd", 200, 4, ErrResponse},
		{"suffix only", "application/jwt", "abcd", 200, 4, ErrResponse},
		{"no Content-Type", "", "abcd", 200, 4, ErrResponse},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, contentType, body = tc.status, tc.contentType, tc.body
			got, err := get(c, srv.URL, tc.max)
			if tc.want == nil {
				if err != nil || string(got) != tc.body {
					t.Fatalf("got %q, %v; want %q", got, err, tc.body)
				}
				return
			}
			if !errors.Is(err, tc.want) || got != nil {
				t.Fatalf("got %q, %v; want %v", got, err, tc.want)
			}
		})
	}

	for _, url := range []string{"http://example.com/x", "https:///x", "https://user:pw@example.com/x", "/relative", "ftp://example.com", "https://[::1"} {
		if _, err := get(c, url, 4); !errors.Is(err, ErrNotHTTPS) {
			t.Errorf("Get(%q): %v, want ErrNotHTTPS", url, err)
		}
	}
}

// TestRedirectToHTTPNeverSent: the client refuses the http hop before sending
// it, so the plain-HTTP server is never contacted; and Get refuses an http
// final URL even from a caller-supplied client without that rule.
func TestRedirectToHTTPNeverSent(t *testing.T) {
	var plainHits atomic.Int32
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		plainHits.Add(1)
		w.Header().Set("Content-Type", "application/statuslist+jwt")
		_, _ = w.Write([]byte("over plain http"))
	}))
	defer plain.Close()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+"/list", http.StatusFound)
	})
	srv, c := tlsServer(t, handler, Options{AllowAddrs: []netip.AddrPort{netip.MustParseAddrPort(plain.Listener.Addr().String())}})
	if _, err := get(c, srv.URL, 100); !errors.Is(err, ErrRedirect) {
		t.Fatalf("redirect to http: %v, want ErrRedirect", err)
	}
	if n := plainHits.Load(); n != 0 {
		t.Fatalf("the http target was contacted %d times", n)
	}

	custom := &http.Client{Transport: srv.Client().Transport}
	if _, err := get(custom, srv.URL, 100); !errors.Is(err, ErrRedirect) {
		t.Fatalf("caller-supplied client landing on http: %v, want ErrRedirect", err)
	}
}
