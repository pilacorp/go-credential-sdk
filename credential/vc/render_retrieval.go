package vc

import (
	"context"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// HTTPFetcher fetches external resources with limits on response size,
// time and redirects. It does not check the address it connects to, so a
// credential can point it at an internal host. Use it only for resources from
// issuers the application trusts; otherwise implement Fetcher.
type HTTPFetcher struct {
	Client          *http.Client
	MaxResponseSize int64
	MaxRedirects    int
	Timeout         time.Duration
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
			if len(via) >= f.MaxRedirects {
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
	if pointer == "" {
		return document, nil
	}
	if err := validateJSONPointer(pointer); err != nil {
		return nil, err
	}
	current := document
	for _, token := range strings.Split(pointer[1:], "/") {
		token = strings.ReplaceAll(strings.ReplaceAll(token, "~1", "/"), "~0", "~")
		switch value := current.(type) {
		case map[string]any:
			var ok bool
			current, ok = value[token]
			if !ok {
				return nil, fmt.Errorf("JSON Pointer segment %.64q not found", token)
			}
		case []any:
			index, ok := jsonPointerArrayIndex(token, len(value))
			if !ok {
				return nil, fmt.Errorf("JSON Pointer array index %.64q is invalid", token)
			}
			current = value[index]
		default:
			return nil, fmt.Errorf("cannot resolve JSON Pointer segment %.64q through %T", token, current)
		}
	}
	return current, nil
}

// jsonPointerArrayIndex parses an RFC 6901 §4 array index: "0" or digits with
// no leading zero, below length. It accepts the same tokens as the selectJsonLd
// implementation in jsonmap, so a pointer resolves the same way for summary and
// html.
func jsonPointerArrayIndex(token string, length int) (int, bool) {
	if token == "" || (len(token) > 1 && token[0] == '0') {
		return 0, false
	}
	for i := 0; i < len(token); i++ {
		if token[i] < '0' || token[i] > '9' {
			return 0, false
		}
	}
	index, err := strconv.Atoi(token)
	return index, err == nil && index < length
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
