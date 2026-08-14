package vcanchor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const (
	defaultSubmitRootPath    = "/api/v1/credentials/external/merkle-roots"
	defaultVerifyReceiptPath = "/api/v1/credentials/external/verify-receipt"
)

type ClientOption func(*ServiceClient)

type ServiceClient struct {
	baseURL       string
	issuerDID     string
	authorization string
	httpClient    *http.Client
}

func NewServiceClient(baseURL, issuerDID string, opts ...ClientOption) *ServiceClient {
	client := &ServiceClient{
		baseURL:    strings.TrimRight(baseURL, "/"),
		issuerDID:  issuerDID,
		httpClient: http.DefaultClient,
	}
	for _, opt := range opts {
		opt(client)
	}
	if client.httpClient == nil {
		client.httpClient = http.DefaultClient
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

func (c *ServiceClient) SubmitRoot(ctx context.Context, req SubmitRootRequest) (*SubmitRootResponse, error) {
	var resp SubmitRootResponse
	body := submitRootBody{
		ExternalTreeID: req.ExternalTreeID,
		Root:           req.Root,
		LeafCount:      req.LeafCount,
		HashScheme:     req.HashScheme,
		LeavesDigest:   req.LeavesDigest,
	}
	if err := c.postJSON(ctx, defaultSubmitRootPath, body, &resp, map[string]string{
		"x-issuer-did": req.IssuerDID,
	}); err != nil {
		return nil, err
	}

	return &resp, nil
}

func (c *ServiceClient) VerifyReceipt(ctx context.Context, receipt Receipt) (*VerifyReceiptResponse, error) {
	var resp VerifyReceiptResponse
	if err := c.postJSON(ctx, defaultVerifyReceiptPath, receipt, &resp, nil); err != nil {
		return nil, err
	}

	return &resp, nil
}

func (c *ServiceClient) postJSON(ctx context.Context, path string, payload, out any, headers map[string]string) error {
	if c == nil {
		return fmt.Errorf("vcanchor: service client is nil")
	}
	if c.baseURL == "" {
		return fmt.Errorf("vcanchor: base url is required")
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
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
	ExternalTreeID string `json:"external_tree_id"`
	Root           string `json:"root"`
	LeafCount      int    `json:"leaf_count"`
	HashScheme     string `json:"hash_scheme"`
	LeavesDigest   string `json:"leaves_digest"`
}
