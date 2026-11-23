package vc

import (
	"context"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/pilacorp/go-credential-sdk/credential/internal/jsonpointer"
)

// HTTPFetcher fetches external resources with limits on response size,
// time and redirects. It does not check the address it connects to, so a
// credential can point it at an internal host. Use it only for resources from
// issuers the application trusts; otherwise implement Fetcher.
type HTTPFetcher struct {
	// Client sends the request; it is required.
	Client *http.Client
	// MaxResponseSize is the largest body read, in bytes; it must be positive.
	MaxResponseSize int64
	// MaxRedirects is the number of redirects followed: 0 refuses every
	// redirect, and a negative value keeps the policy of Client.
	MaxRedirects int
	// Timeout bounds the whole request; zero or less sets no timeout.
	Timeout time.Duration
}

func (f HTTPFetcher) Fetch(ctx context.Context, ref TemplateReference) ([]byte, error) {
	client := f.Client
	if client == nil {
		return nil, fmt.Errorf("http client is required")
	}
	limit := f.MaxResponseSize
	if limit <= 0 {
		return nil, fmt.Errorf("max response size must be positive")
	}
	requestCtx := ctx
	var cancel context.CancelFunc
	if f.Timeout > 0 {
		requestCtx, cancel = context.WithTimeout(ctx, f.Timeout)
		defer cancel()
	}
	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, ref.ID, nil)
	if err != nil {
		return nil, fmt.Errorf("create template request: %w", err)
	}
	clientCopy := *client
	if f.MaxRedirects >= 0 {
		clientCopy.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			// via holds the requests already sent, so one redirect gives a length of 1.
			if len(via) > f.MaxRedirects {
				return fmt.Errorf("maximum redirect count %d exceeded", f.MaxRedirects)
			}
			return nil
		}
	}
	resp, err := clientCopy.Do(req)
	if err != nil {
		// The error carries the request URL or a redirect Location, both chosen
		// by the credential or the server.
		return nil, fmt.Errorf("fetch template: %w", boundedError{err})
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("fetch template: unexpected HTTP status %.64q", resp.Status)
	}
	if ref.MediaType != "" {
		// Both values are quoted only at their start: one comes from the
		// credential, the other from the server.
		contentType := resp.Header.Get("Content-Type")
		if !isMediaType(contentType, ref.MediaType) {
			return nil, fmt.Errorf("template media type %.64q does not match expected %.64q", contentType, ref.MediaType)
		}
	}
	// One byte past the limit tells a body at the limit from a longer one.
	// At the largest int64 there is no longer body to tell apart.
	readLimit := limit
	if readLimit < math.MaxInt64 {
		readLimit++
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, readLimit))
	if err != nil {
		return nil, fmt.Errorf("read template response: %w", err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("template response exceeds %d bytes", limit)
	}
	return data, nil
}

// resolveJSONPointer resolves an RFC 6901 pointer against a JSON-like value.
func resolveJSONPointer(document any, pointer string) (any, error) {
	return jsonpointer.Resolve(document, pointer)
}

// boundedError shortens a cause whose text holds input from a credential or a
// server, and still unwraps to the cause. It keeps both ends: net/http puts the
// URL first and the reason (timeout, refused, redirect limit) last.
type boundedError struct{ err error }

const boundedErrorHalf = 256

func (e boundedError) Error() string {
	text := e.err.Error()
	if len(text) <= 2*boundedErrorHalf {
		return text
	}
	// Cutting by byte can split a rune, so invalid UTF-8 in the kept ends is dropped.
	return strings.ToValidUTF8(text[:boundedErrorHalf], "") + "…" + strings.ToValidUTF8(text[len(text)-boundedErrorHalf:], "")
}

func (e boundedError) Unwrap() error { return e.err }
