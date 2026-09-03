package vcanchor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const defaultSubmitRootPath = "/api/v1/credentials/merkle-roots"

type ClientOption func(*ServiceClient)

type ServiceClient struct {
	baseURL       string
	issuerDID     string
	authorization string
	httpClient    *http.Client
}

// defaultHTTPTimeout bounds a request when the caller sets no deadline of their own,
// because http.DefaultClient has none at all.
//
// SubmitRoot no longer waits for mining: the service records the root, queues it for
// anchoring and answers, so this only has to cover a normal API round trip. Callers
// who want different behaviour still have WithHTTPClient.
const defaultHTTPTimeout = 30 * time.Second

func newDefaultHTTPClient() *http.Client {
	return &http.Client{Timeout: defaultHTTPTimeout}
}

func NewServiceClient(baseURL, issuerDID string, opts ...ClientOption) *ServiceClient {
	client := &ServiceClient{
		baseURL:    strings.TrimRight(baseURL, "/"),
		issuerDID:  issuerDID,
		httpClient: newDefaultHTTPClient(),
	}
	for _, opt := range opts {
		opt(client)
	}
	if client.httpClient == nil {
		client.httpClient = newDefaultHTTPClient()
	}

	return client
}

func WithHTTPClient(httpClient *http.Client) ClientOption {
	return func(client *ServiceClient) {
		client.httpClient = httpClient
	}
}

func WithAuthorization(authorization string) ClientOption {
	return func(client *ServiceClient) {
		client.authorization = authorization
	}
}

// SubmitRoot hands a root to the service for anchoring. It returns as soon as the
// root is recorded, so a first submit answers StatusPending with an empty TxHash;
// anchoring happens asynchronously. Call it again with the same batch to poll — the
// service returns the recorded root, and StatusAnchored with a TxHash once it is on
// chain. Resubmitting does not queue the root twice.
func (c *ServiceClient) SubmitRoot(ctx context.Context, req SubmitRootRequest) (*SubmitRootResponse, error) {
	issuerDID, err := c.submitRootIssuerDID(req.IssuerDID)
	if err != nil {
		return nil, err
	}

	var resp SubmitRootResponse
	body := submitRootBody{
		Root:      req.Root,
		LeafCount: req.LeafCount,
	}
	if err := c.postJSON(ctx, defaultSubmitRootPath, body, &resp, map[string]string{
		"x-issuer-did": issuerDID,
	}); err != nil {
		return nil, err
	}

	return &resp, nil
}

// GetRoot reads a submitted root's anchoring state without submitting anything. This
// is the call to poll with: it needs only read permission, and a tree that was never
// submitted comes back as an error rather than being submitted as a side effect.
func (c *ServiceClient) GetRoot(ctx context.Context, issuerDID, root string, leafCount int) (*SubmitRootResponse, error) {
	resolvedIssuerDID, err := c.submitRootIssuerDID(issuerDID)
	if err != nil {
		return nil, err
	}

	var resp SubmitRootResponse
	if err := c.getJSON(ctx, defaultSubmitRootPath, url.Values{
		"root":       {root},
		"leaf_count": {strconv.Itoa(leafCount)},
	}, &resp, map[string]string{
		"x-issuer-did": resolvedIssuerDID,
	}); err != nil {
		return nil, err
	}

	return &resp, nil
}

func (c *ServiceClient) submitRootIssuerDID(reqIssuerDID string) (string, error) {
	if c == nil {
		return "", fmt.Errorf("vcanchor: service client is nil")
	}
	if c.issuerDID != "" && reqIssuerDID != "" && c.issuerDID != reqIssuerDID {
		return "", fmt.Errorf("vcanchor: issuer_did does not match service client issuer")
	}
	if c.issuerDID != "" {
		return c.issuerDID, nil
	}

	return reqIssuerDID, nil
}

func (c *ServiceClient) postJSON(ctx context.Context, path string, payload, out any, headers map[string]string) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	return c.doJSON(ctx, http.MethodPost, path, bytes.NewReader(raw), out, headers)
}

func (c *ServiceClient) getJSON(ctx context.Context, path string, query url.Values, out any, headers map[string]string) error {
	if len(query) > 0 {
		path += "?" + query.Encode()
	}

	return c.doJSON(ctx, http.MethodGet, path, nil, out, headers)
}

func (c *ServiceClient) doJSON(ctx context.Context, method, path string, body io.Reader, out any, headers map[string]string) error {
	if c == nil {
		return fmt.Errorf("vcanchor: service client is nil")
	}
	if c.baseURL == "" {
		return fmt.Errorf("vcanchor: base url is required")
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	if c.issuerDID != "" {
		req.Header.Set("x-issuer-did", c.issuerDID)
	}
	if c.authorization != "" {
		req.Header.Set("Authorization", c.authorization)
	}
	for key, value := range headers {
		if value != "" {
			req.Header.Set(key, value)
		}
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("vcanchor: authen service returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	return json.NewDecoder(resp.Body).Decode(out)
}

type submitRootBody struct {
	Root      string `json:"root"`
	LeafCount int    `json:"leaf_count"`
}
