package provider

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/pilacorp/go-credential-sdk/credential/common/model"
)

type defaultProvider struct {
	baseURL string
	client  *http.Client
}

func NewDefaultProvider(baseURL string) Provider {
	return &defaultProvider{
		baseURL: baseURL,
		client:  &http.Client{Timeout: 10 * time.Second},
	}
}

func (p *defaultProvider) DIDResolver(did string) (*model.DIDDocument, error) {
	// Construct and encode API URL
	encodedDID := url.PathEscape(did)
	apiURL := p.baseURL + "/" + encodedDID

	// Perform HTTP GET request
	resp, err := p.client.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("failed to make HTTP request to DID resolver: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DID resolver API returned non-200 status: %s", resp.Status)
	}

	// Read and parse response
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body from DID resolver: %w", err)
	}

	var doc model.DIDDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("failed to unmarshal DID document JSON: %w", err)
	}

	return &doc, nil
}
func (p *defaultProvider) SchemaResolver(url string) (*model.SchemaDocument, error) {

	return &model.SchemaDocument{}, nil
}
func (p *defaultProvider) SignProof(signingInput []byte, signer string) (*model.Proof, error) {

	return &model.Proof{}, nil
}
