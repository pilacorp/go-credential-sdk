// Package safehttp fetches documents whose URL comes from untrusted input.
//
// draft-ietf-oauth-sd-jwt-vc-19 §3 and §7.1: an https URL with a host and no
// userinfo on every hop (RFC 9110 §4.2.2, §4.2.4), a bounded number of
// redirects, time and size bounds, a 2xx status (RFC 9110 §15.3) of the
// expected media type, and no connection to an address that is not globally
// reachable. draft-ietf-oauth-status-list-21 §8.2: a 2xx status and the
// registered media type; §11.4 (redirect loops): bounded by the redirect
// limit. Applying the sd-jwt-vc-19 rules to a status list uri is this
// package's policy: status-list-21 §6.2 leaves further restrictions on that
// uri to the Relying Party, so a caller may allow http (Limits.AllowHTTP).
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
	"slices"
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
	// AllowHTTP lets the URL and every redirect target be http as well as
	// https, for a caller whose standard leaves the scheme to it; the host
	// and userinfo rules of HTTPSURL still hold.
	AllowHTTP bool
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
	// handshake; these bounds do. Every caller's fetch ends within 5 seconds,
	// so a dial or handshake past that serves only a fetch that has failed,
	// and holds a socket to a host the token may have chosen.
	dialer := &net.Dialer{Timeout: 5 * time.Second, Control: control}
	return &http.Client{Transport: &http.Transport{
		Proxy:                  nil,
		DialContext:            dialer.DialContext,
		TLSHandshakeTimeout:    5 * time.Second,
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

// HTTPSURL reports whether u is an https URL with a host and no userinfo, the
// only URLs Get requests and follows unless Limits.AllowHTTP also lets http
// ones through: draft-ietf-oauth-sd-jwt-vc-19 §3 (HTTPS only), RFC 9110 §4.2.2
// (an https URI with an empty host is invalid; dialing ":443" reaches the local
// host) and §4.2.4 (a recipient SHOULD treat userinfo as an error, since it can
// obscure the authority; this package always does). A nil u is false.
func HTTPSURL(u *url.URL) bool {
	return u != nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil
}

// allows reports whether Get may request u: HTTPSURL, or with AllowHTTP the
// same rules for an http URL.
func (l Limits) allows(u *url.URL) bool {
	if l.AllowHTTP && u != nil && u.Scheme == "http" {
		return u.Hostname() != "" && u.User == nil
	}
	return HTTPSURL(u)
}

// redirectRefusal is the text of a redirect Get's CheckRedirect refuses; its
// own type lets fetchError show that text.
type redirectRefusal string

func (r redirectRefusal) Error() string { return string(r) }

// fetchErr is the error Get returns when net/http fails, requesting or
// reading the body. Its text never holds the request URL or a redirect
// target: net/http puts the request URL with its query, or a Location with
// its userinfo, in the *url.Error and in its cause (RFC 3986 §7.5). Unwrap
// returns that cause as net/http built it.
type fetchErr struct {
	text  string
	cause error
}

func (e *fetchErr) Error() string { return "safehttp: Get: " + e.text }
func (e *fetchErr) Unwrap() error { return e.cause }

// fetchError takes the cause out of the *url.Error and picks the text of the
// first class it matches: a refusal of Get, a context error, a *net.OpError,
// then a fixed text naming what failed for everything else, a caller's
// CheckRedirect or Transport error included, since its text cannot be told
// from net/http's. step names a stage after the request, such as "reading
// body", and goes before the text; it is empty for the request itself.
func fetchError(step string, err error) error {
	cause := err
	var ue *url.Error
	if errors.As(err, &ue) {
		cause = ue.Err
	}
	var refusal redirectRefusal
	var op *net.OpError
	var text string
	switch {
	case errors.As(cause, &refusal):
		text = string(refusal)
	case errors.Is(cause, context.Canceled):
		text = context.Canceled.Error()
	case errors.Is(cause, context.DeadlineExceeded):
		text = context.DeadlineExceeded.Error()
	case errors.As(cause, &op):
		// Op, network, ip:port and the cause, such as ErrBlockedAddress or a
		// DNS error naming the host; through a proxy the caller configured,
		// it can be TLS text quoting certificate names the proxy chose. The
		// host can come from untrusted input of any length and script, so the
		// text is cut and quoted.
		text = fmt.Sprintf("%.200q", op.Error())
	default:
		if step == "" {
			return &fetchErr{text: "request failed", cause: cause}
		}
		return &fetchErr{text: step + " failed", cause: cause}
	}
	if step != "" {
		text = step + ": " + text
	}
	return &fetchErr{text: text, cause: cause}
}

// schemes names what allows accepts, for errors.
func (l Limits) schemes() string {
	if l.AllowHTTP {
		return "http or https"
	}
	return "https"
}

// Get fetches rawURL and returns the body and the response header. rawURL and
// every redirect target must pass HTTPSURL (with l.AllowHTTP, or be an http
// URL with a host and no userinfo), and at most l.MaxRedirects
// redirects are followed, both checked before the next request is sent. The
// whole fetch ends within l.Timeout. The status must be 2xx, and the media
// type of Content-Type must be one of mediaTypes (ASCII case ignored,
// parameters allowed); the list, joined by ", ", is also sent as Accept (RFC
// 9110 §12.5.1). An empty list matches no response. A body over l.MaxBytes is
// an error, never truncated. Accept-Encoding is identity, so l.MaxBytes counts
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
//
// The text of every error Get returns never holds the request URL or a
// redirect target. Its own checks (arguments, URL, status, content type,
// body size) write text of this package. An error of net/http, requesting or
// reading the body, goes through an allowlist: its text is a redirect Get
// refused, a context error, a *net.OpError cut to 200 characters and quoted,
// or else a fixed text naming the step that failed. The text of a
// *net.OpError includes its cause, which through a proxy configured in c can
// quote certificate names; NewClient sets no proxy. errors.Is and errors.As
// still reach the cause (context.Canceled,
// context.DeadlineExceeded, ErrBlockedAddress, an error of c), but not the
// *url.Error that carried it; printing the cause itself prints net/http's
// text, which may hold the URL.
func Get(ctx context.Context, c *http.Client, rawURL string, mediaTypes []string, l Limits) ([]byte, http.Header, error) {
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
	if err != nil || !l.allows(u) {
		return nil, nil, fmt.Errorf("safehttp: URL is not %s with a host and no userinfo", l.schemes())
	}

	ctx, cancel := context.WithTimeout(ctx, l.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, nil, fetchError("", err)
	}
	// Callers may rely on Accept and Accept-Encoding being the same on every
	// request of a Get, redirects included, unless the client's CheckRedirect
	// or Transport changes them: a cache matching Vary does (RFC 9111 §4.1).
	req.Header.Set("Accept", strings.Join(mediaTypes, ", "))
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
		if !l.allows(r.URL) {
			return redirectRefusal("redirect to a URL that is not " + l.schemes() + " with a host and no userinfo")
		}
		if len(via) > l.MaxRedirects {
			return redirectRefusal(fmt.Sprintf("more than %d redirects", l.MaxRedirects))
		}
		return nil
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, fetchError("", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, nil, fmt.Errorf("safehttp: status %d", resp.StatusCode)
	}
	mt, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || !slices.ContainsFunc(mediaTypes, func(want string) bool { return strings.EqualFold(mt, want) }) {
		return nil, nil, fmt.Errorf("safehttp: content type is not %s", strings.Join(mediaTypes, " or "))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, l.MaxBytes+1))
	if err != nil {
		return nil, nil, fetchError("reading body", err)
	}
	if int64(len(body)) > l.MaxBytes {
		return nil, nil, fmt.Errorf("safehttp: body over %d bytes", l.MaxBytes)
	}
	return body, resp.Header, nil
}
