// Package safehttp fetches documents whose URL comes from untrusted input.
//
// draft-ietf-oauth-sd-jwt-vc-19 §3 and §7.1: an https URL with a host on every
// hop (RFC 9110 §4.2.2), a bounded number of redirects, time and size bounds,
// a 2xx status (RFC 9110 §15.3) of the expected media type, and no connection
// to an address that is not globally reachable. draft-ietf-oauth-status-list-21
// §8.2: a 2xx status and the registered media type; §11.4 (redirect loops):
// bounded by the redirect limit. Applying the sd-jwt-vc-19 rules to a status
// list uri is this package's policy: status-list-21 §6.2 leaves further
// restrictions on that uri to the Relying Party.
//
// The address check sits in the dialer of NewClient, so it sees the address
// actually connected to, after DNS resolution and on every redirect. It cannot
// know hosts reachable only inside the caller's own network (§7.1); those are
// left to the deployment's egress policy.
package safehttp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// ErrBlockedAddress: the dialer of NewClient refused an address Blocked
// reports. It stays visible to errors.Is through the error Get returns.
var ErrBlockedAddress = errors.New("safehttp: blocked address")

// Limits bound one call of Get. The timeout and the byte cap guard different
// things: a body under the cap can still stall forever, and a fast server can
// still send too much.
type Limits struct {
	Timeout      time.Duration // whole fetch: connecting, redirects, headers and body; must be > 0
	MaxRedirects int           // redirects followed; 0 or less follows none
	MaxBytes     int64         // largest body accepted; 0 < MaxBytes < math.MaxInt64
}

// maxHeaderBytes caps response headers, which would otherwise default to
// 10 MB, far above any body cap.
const maxHeaderBytes = 64 << 10

// NewClient returns the client to pass to Get. Its dialer refuses every
// address Blocked reports, and it never uses a proxy from the environment,
// since a proxy would connect on its behalf and hide the real address. Create
// it once and reuse it: it keeps idle connections.
func NewClient() *http.Client {
	// net/http keeps dialing after the request is canceled, to reuse the
	// connection, so Limits.Timeout does not end a stalled connect or TLS
	// handshake; these bounds do (the values of http.DefaultTransport).
	dialer := &net.Dialer{Timeout: 30 * time.Second, Control: control}
	return &http.Client{Transport: &http.Transport{
		Proxy:                  nil,
		DialContext:            dialer.DialContext,
		TLSHandshakeTimeout:    10 * time.Second,
		ForceAttemptHTTP2:      true,
		MaxIdleConns:           100,
		IdleConnTimeout:        90 * time.Second,
		MaxResponseHeaderBytes: maxHeaderBytes,
	}}
}

func control(_, address string, _ syscall.RawConn) error {
	// An address that is not ip:port is refused too: the dialer passes an
	// empty host unresolved (":443"), and dialing it reaches the local host.
	ap, err := netip.ParseAddrPort(address)
	if err != nil || Blocked(ap.Addr()) {
		return fmt.Errorf("%w: %s", ErrBlockedAddress, address)
	}
	return nil
}

// HTTPSURL reports whether u is an https URL with a host, the only URLs Get
// requests and follows: draft-ietf-oauth-sd-jwt-vc-19 §3 (HTTPS only) and RFC
// 9110 §4.2.2 (an https URI with an empty host is invalid; dialing ":443"
// reaches the local host).
func HTTPSURL(u *url.URL) bool {
	return u.Scheme == "https" && u.Hostname() != ""
}

// Get fetches rawURL and returns the body and the response header. rawURL and
// every redirect target must be https with a host, and at most l.MaxRedirects
// redirects are followed, both checked before the next request is sent. The
// whole fetch ends within l.Timeout. The status must be 2xx, and the media
// type of Content-Type must be mediaType (ASCII case ignored, parameters
// allowed); mediaType is also sent as Accept. A body over l.MaxBytes is an
// error, never truncated. Accept-Encoding is identity, so l.MaxBytes counts
// the bytes the server sends: with transparent decompression a stream of
// empty deflate blocks adds nothing to the body and only l.Timeout would end
// it. A body sent compressed anyway is returned as is and fails the caller's
// parsing.
//
// The checks above judge the URLs Get sees and the response c returns,
// whatever c. The address check exists only in the transport of NewClient.
// Another client is trusted code: its Transport brings its own dialing, proxy
// and TLS rules and can send a request elsewhere, and l.Timeout bounds it only
// if it honours the request context. Its CheckRedirect runs before these
// checks, so a URL it rewrites is checked too.
func Get(ctx context.Context, c *http.Client, rawURL, mediaType string, l Limits) ([]byte, http.Header, error) {
	if c == nil {
		return nil, nil, errors.New("safehttp: nil client")
	}
	if l.Timeout <= 0 {
		return nil, nil, fmt.Errorf("safehttp: timeout %v out of range", l.Timeout)
	}
	// MaxBytes+1 must not overflow: a negative limit reads nothing and an empty
	// body would pass as a success.
	if l.MaxBytes <= 0 || l.MaxBytes == math.MaxInt64 {
		return nil, nil, fmt.Errorf("safehttp: max bytes %d out of range", l.MaxBytes)
	}
	u, err := url.Parse(rawURL)
	if err != nil || !HTTPSURL(u) {
		return nil, nil, errors.New("safehttp: URL is not https with a host")
	}

	ctx, cancel := context.WithTimeout(ctx, l.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("safehttp: %w", err)
	}
	req.Header.Set("Accept", mediaType)
	req.Header.Set("Accept-Encoding", "identity")

	client := *c
	next := c.CheckRedirect
	client.CheckRedirect = func(r *http.Request, via []*http.Request) error {
		// The caller's check runs first so that ours judge the URL actually
		// requested, even one it rewrote.
		if next != nil {
			if err := next(r, via); err != nil {
				return err
			}
		}
		if !HTTPSURL(r.URL) {
			return errors.New("safehttp: redirect to a URL that is not https with a host")
		}
		if len(via) > l.MaxRedirects {
			return fmt.Errorf("safehttp: more than %d redirects", l.MaxRedirects)
		}
		return nil
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("safehttp: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, nil, fmt.Errorf("safehttp: status %d", resp.StatusCode)
	}
	if mt, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type")); err != nil || !strings.EqualFold(mt, mediaType) {
		return nil, nil, fmt.Errorf("safehttp: content type is not %s", mediaType)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, l.MaxBytes+1))
	if err != nil {
		return nil, nil, fmt.Errorf("safehttp: reading body: %w", err)
	}
	if int64(len(body)) > l.MaxBytes {
		return nil, nil, fmt.Errorf("safehttp: body over %d bytes", l.MaxBytes)
	}
	return body, resp.Header, nil
}
