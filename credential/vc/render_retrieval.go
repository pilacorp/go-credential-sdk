package vc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// HTTPTemplateFetcher retrieves external templates with bounded response size
// and caller-controlled HTTP behavior.
type HTTPTemplateFetcher struct {
	Client          *http.Client
	MaxResponseSize int64
	MaxRedirects    int
	Timeout         time.Duration
}

func (f HTTPTemplateFetcher) Fetch(ctx context.Context, ref TemplateReference) ([]byte, error) {
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
		return nil, fmt.Errorf("fetch template: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("fetch template: unexpected HTTP status %s", resp.Status)
	}
	if ref.MediaType != "" {
		contentType := strings.TrimSpace(strings.Split(resp.Header.Get("Content-Type"), ";")[0])
		if contentType != ref.MediaType {
			return nil, fmt.Errorf("template media type %q does not match expected %q", contentType, ref.MediaType)
		}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read template response: %w", err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("template response exceeds %d bytes", limit)
	}
	return data, nil
}

func (f HTTPTemplateFetcher) FetchRenderMethod(ctx context.Context, id string) ([]byte, error) {
	return f.Fetch(ctx, TemplateReference{ID: id})
}

// ResolveJSONPointer resolves an RFC 6901 pointer against a JSON-like value.
func ResolveJSONPointer(document any, pointer string) (any, error) {
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
				return nil, fmt.Errorf("JSON Pointer segment %q not found", token)
			}
		case []any:
			var index int
			if err := json.Unmarshal([]byte(token), &index); err != nil || index < 0 || index >= len(value) {
				return nil, fmt.Errorf("JSON Pointer array index %q is invalid", token)
			}
			current = value[index]
		default:
			return nil, fmt.Errorf("cannot resolve JSON Pointer segment %q through %T", token, current)
		}
	}
	return current, nil
}
