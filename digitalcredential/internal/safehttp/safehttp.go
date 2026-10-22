// Package safehttp is the HTTP client every fetch of the module goes through
// (the status list Checker now, issuermeta later), so that a URL taken from a
// credential or from issuer metadata cannot reach an internal address.
//
// The check sits at the dialer (net.Dialer.Control), which sees the address
// actually connected to, after DNS resolution. It therefore also covers every
// redirect hop and every DNS answer, including a name that resolves to a
// public address once and to a private one the next time (rebinding).
package safehttp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"syscall"
	"time"
)

// Defaults shared by the status list Checker and issuermeta (spec S3, draft 19
// §3 of SD-JWT VC).
const (
	DefaultTimeout      = 5 * time.Second
	DefaultMaxRedirects = 3
	DefaultMaxBytes     = 64 << 10
)

var (
	// ErrBlockedAddress: the connection would go to a loopback, private,
	// link-local, unspecified, multicast or otherwise internal address.
	ErrBlockedAddress = errors.New("digitalcredential: blocked address")
	// ErrRedirect: a redirect to a non-HTTPS URL, or more redirects than
	// allowed.
	ErrRedirect = errors.New("digitalcredential: redirect refused")
	// ErrNotHTTPS: the URL to fetch is not an absolute https URL with a host.
	ErrNotHTTPS = errors.New("digitalcredential: URL is not https")
	// ErrResponse: the status is not 200, or the Content-Type is not the one
	// required.
	ErrResponse = errors.New("digitalcredential: unexpected response")
	// ErrTooLarge: the body is larger than the limit.
	ErrTooLarge = errors.New("digitalcredential: response too large")
)

// Options configures NewClient.
type Options struct {
	// Timeout bounds dialing, the TLS handshake and the whole request.
	// 0 means DefaultTimeout.
	Timeout time.Duration
	// MaxRedirects is the number of redirects followed. 0 means
	// DefaultMaxRedirects; a negative value follows none.
	MaxRedirects int
	// AllowPrivateNetworks turns the address check off. Tests and local
	// development only.
	AllowPrivateNetworks bool

	// AllowAddrs lets these exact address:port pairs through the check while
	// every other internal address stays blocked. Tests only: it lets an
	// httptest server on 127.0.0.1 answer while a redirect to another local
	// port is still refused.
	AllowAddrs []netip.AddrPort
	// TLSConfig replaces the default TLS configuration. Tests only (to trust
	// an httptest certificate).
	TLSConfig *tls.Config
}

// NewClient returns an http.Client whose dialer refuses internal addresses,
// which follows only HTTPS redirects and at most MaxRedirects of them, and
// which never uses a proxy from the environment (a proxy would make the dialer
// see the proxy's address instead of the target's).
func NewClient(o Options) *http.Client {
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	maxRedirects := o.MaxRedirects
	switch {
	case maxRedirects == 0:
		maxRedirects = DefaultMaxRedirects
	case maxRedirects < 0:
		maxRedirects = 0
	}
	dialer := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 30 * time.Second,
		Control:   control(o.AllowPrivateNetworks, slices.Clone(o.AllowAddrs)),
	}
	var tlsConfig *tls.Config
	if o.TLSConfig != nil {
		tlsConfig = o.TLSConfig.Clone()
	}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		TLSClientConfig:       tlsConfig,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          16,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
	}
	return &http.Client{
		Transport:     transport,
		Timeout:       timeout,
		CheckRedirect: checkRedirect(maxRedirects),
	}
}

// control is the net.Dialer.Control hook. address is the resolved ip:port the
// socket is about to connect to. Anything that does not parse is refused.
func control(allowPrivate bool, allow []netip.AddrPort) func(network, address string, _ syscall.RawConn) error {
	return func(network, address string, _ syscall.RawConn) error {
		ap, err := netip.ParseAddrPort(address)
		if err != nil {
			return fmt.Errorf("%w: cannot parse %q: %v", ErrBlockedAddress, address, err)
		}
		if allowPrivate {
			return nil
		}
		plain := netip.AddrPortFrom(ap.Addr().WithZone(""), ap.Port())
		if slices.Contains(allow, plain) {
			return nil
		}
		if Blocked(ap.Addr()) {
			return fmt.Errorf("%w: %s", ErrBlockedAddress, ap.Addr())
		}
		return nil
	}
}

var (
	// thisNetwork is 0.0.0.0/8: on Linux, connecting to 0.0.0.0 reaches the
	// local host.
	thisNetwork = netip.MustParsePrefix("0.0.0.0/8")
	// sharedAddressSpace is 100.64.0.0/10 (RFC 6598, carrier-grade NAT); some
	// clouds serve instance metadata there (100.100.100.200).
	sharedAddressSpace = netip.MustParsePrefix("100.64.0.0/10")
	broadcast          = netip.MustParseAddr("255.255.255.255")
	// nat64 is the well-known NAT64 prefix 64:ff9b::/96 (RFC 6052): the last
	// four bytes are an IPv4 address that a NAT64 gateway connects to.
	nat64 = netip.MustParsePrefix("64:ff9b::/96")
)

// Blocked reports whether a connection to a must be refused: loopback,
// private (RFC 1918, fc00::/7), link-local (169.254/16, fe80::/10),
// unspecified, multicast, and the IPv4-mapped (::ffff:a.b.c.d) and NAT64
// (64:ff9b::a.b.c.d) forms of each. 0.0.0.0/8, 100.64.0.0/10 and
// 255.255.255.255 are refused too.
func Blocked(a netip.Addr) bool {
	a = a.WithZone("")
	if !a.IsValid() {
		return true
	}
	if a.Is4In6() {
		a = a.Unmap()
	}
	if nat64.Contains(a) {
		b := a.As16()
		a = netip.AddrFrom4([4]byte(b[12:16]))
	}
	return a.IsLoopback() ||
		a.IsPrivate() ||
		a.IsLinkLocalUnicast() ||
		a.IsUnspecified() ||
		a.IsMulticast() ||
		a.IsLinkLocalMulticast() ||
		a.IsInterfaceLocalMulticast() ||
		thisNetwork.Contains(a) ||
		sharedAddressSpace.Contains(a) ||
		a == broadcast
}

func checkRedirect(maxRedirects int) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) > maxRedirects {
			return fmt.Errorf("%w: more than %d redirects", ErrRedirect, maxRedirects)
		}
		if req.URL.Scheme != "https" {
			return fmt.Errorf("%w: redirect to %s, not https", ErrRedirect, req.URL.Redacted())
		}
		return nil
	}
}

// Get fetches rawURL with "Accept: mediaType" and returns the body when:
//   - rawURL is an absolute https URL with a host, and so is the final URL
//     after redirects (checked here too, so a caller-supplied client cannot
//     land on http);
//   - the status is 200;
//   - the Content-Type media type equals mediaType (parameters such as
//     charset are allowed, case is ignored as RFC 9110 requires);
//   - the body is at most maxBytes long: maxBytes+1 bytes are read, so an
//     oversized body is an error, never truncated.
func Get(ctx context.Context, c *http.Client, rawURL, mediaType string, maxBytes int64) ([]byte, http.Header, error) {
	if err := checkHTTPS(rawURL); err != nil {
		return nil, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrNotHTTPS, err)
	}
	req.Header.Set("Accept", mediaType)
	resp, err := c.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.Request != nil && resp.Request.URL.Scheme != "https" {
		return nil, nil, fmt.Errorf("%w: final URL is not https", ErrRedirect)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("%w: status %d", ErrResponse, resp.StatusCode)
	}
	got, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || got != mediaType {
		return nil, nil, fmt.Errorf("%w: Content-Type %q, want %s", ErrResponse, resp.Header.Get("Content-Type"), mediaType)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, nil, fmt.Errorf("%w: reading body: %v", ErrResponse, err)
	}
	if int64(len(body)) > maxBytes {
		return nil, nil, fmt.Errorf("%w: body over %d bytes", ErrTooLarge, maxBytes)
	}
	return body, resp.Header, nil
}

func checkHTTPS(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrNotHTTPS, err)
	}
	if u.Scheme != "https" || u.Host == "" || u.Hostname() == "" || u.User != nil {
		return fmt.Errorf("%w: %q", ErrNotHTTPS, u.Redacted())
	}
	return nil
}
