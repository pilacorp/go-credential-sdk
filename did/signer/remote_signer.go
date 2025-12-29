package signer

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// RemoteSigner is a signer that signs a payload using a remote API
type RemoteSigner struct {
	endpoint string
	apiKey   string
	client   *http.Client
}

// NewRemoteSigner creates a new RemoteSigner
func NewRemoteSigner(endpoint, apiKey string) (Signer, error) {
	if strings.TrimSpace(endpoint) == "" {
		return nil, fmt.Errorf("endpoint required")
	}

	return &RemoteSigner{
		endpoint: endpoint,
		apiKey:   apiKey,
		client:   &http.Client{Timeout: 10 * time.Second},
	}, nil
}

// Sign signs a payload using the remote API
func (s *RemoteSigner) Sign(payload []byte) ([]byte, error) {
	if len(payload) != 32 {
		return nil, fmt.Errorf("payload must be 32 bytes, got %d", len(payload))
	}

	reqBody, _ := json.Marshal(map[string]any{
		"payload_hex": hex.EncodeToString(payload),
	})

	req, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		s.endpoint,
		bytes.NewReader(reqBody),
	)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	if s.apiKey != "" {
		req.Header.Set("x-api-key", s.apiKey)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("remote signer http %d", resp.StatusCode)
	}

	var out struct {
		SignatureHex string `json:"signature_hex"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}

	sig, err := hex.DecodeString(strings.TrimPrefix(out.SignatureHex, "0x"))
	if err != nil {
		return nil, err
	}
	if len(sig) != 65 {
		return nil, fmt.Errorf("invalid signature length %d", len(sig))
	}

	return sig, nil
}
