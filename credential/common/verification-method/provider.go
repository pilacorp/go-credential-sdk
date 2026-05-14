package verificationmethod

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// ResolverProvider resolves a DID Document by DID.
//
// Implementations should only concern themselves with fetching/parsing a DID
// document. Higher-level operations (VM selection, key extraction, purpose
// checks) are provided as helper functions in this package.
//
// ctx is required so callers can propagate cancellation and deadlines to
// the underlying I/O (HTTP, gRPC, etc.). Implementations that do no I/O
// (e.g. an in-memory test resolver) may ignore it.
type ResolverProvider interface {
	ResolveDocument(ctx context.Context, did string) (*DIDDocument, error)
}

// HTTPResolver fetches DID Documents from a Pila-style HTTP DID resolver
// endpoint (`baseURL/<did>` returning JSON). It implements ResolverProvider
// with a single method — all higher-level operations (VM selection, key
// extraction, purpose checks) live as free functions in this package so
// callers that already have a resolved document (e.g. from gRPC) can use
// them without going through HTTP.
type HTTPResolver struct {
	baseURL string
	client  *http.Client
}

var defaultHTTPClient = &http.Client{
	Timeout: 10 * time.Second,
}

// Option configures HTTPResolver construction.
type Option func(*HTTPResolver)

// WithHTTPClient overrides the default HTTP client (10s timeout). Pass nil
// to keep the default.
func WithHTTPClient(client *http.Client) Option {
	return func(r *HTTPResolver) {
		if client == nil {
			return
		}
		r.client = client
	}
}

// NewHTTPResolver creates an HTTP-backed ResolverProvider.
func NewHTTPResolver(baseURL string, opts ...Option) *HTTPResolver {
	r := &HTTPResolver{
		baseURL: baseURL,
		client:  defaultHTTPClient,
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// ResolveDocument fetches and parses the DID Document for the given DID.
// Returns an error when did is empty, the HTTP call fails, the response
// status is non-2xx, or the body fails to decode as a DID Document.
func (r *HTTPResolver) ResolveDocument(ctx context.Context, did string) (*DIDDocument, error) {
	if did == "" {
		return nil, fmt.Errorf("did is empty")
	}

	apiURL := r.baseURL + "/" + url.PathEscape(did)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build HTTP request: %w", err)
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make HTTP request to DID resolver: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DID resolver API returned non-200 status: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body from DID resolver: %w", err)
	}

	var doc DIDDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("failed to unmarshal DID document JSON: %w", err)
	}
	return &doc, nil
}
