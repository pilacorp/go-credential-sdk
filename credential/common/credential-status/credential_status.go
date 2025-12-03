package credentialstatus

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/pilacorp/go-credential-sdk/credential/common/util"
)

// Client is a simple HTTP client for fetching credential status information
// from a statusListCredential URL.
type Client struct {
	httpClient *http.Client
}

// NewClient creates a new credential status client with a sensible default timeout.
func NewClient() *Client {
	return &Client{
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// FetchAndCheckRevocation fetches the status list credential from the given
// statusListCredential URL and checks whether the credential at the given
// position is revoked.
func FetchAndCheckRevocation(statusListCredentialURL string, position int) (bool, error) {
	client := NewClient()

	resp, err := client.FetchStatusListCredential(statusListCredentialURL)
	if err != nil {
		return false, err
	}

	return IsRevoked(position, resp.Data.CredentialSubject)
}

// FetchStatusListCredential fetches and parses the status list credential
// located at the given statusListCredential URL.
func (c *Client) FetchStatusListCredential(statusListCredentialURL string) (*StatusListCredentialResponse, error) {
	if statusListCredentialURL == "" {
		return nil, fmt.Errorf("statusListCredential URL is empty")
	}

	resp, err := c.httpClient.Get(statusListCredentialURL)
	if err != nil {
		return nil, fmt.Errorf("failed to call status list credential endpoint: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status list credential API returned non-200 status: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read status list credential response body: %w", err)
	}

	var result StatusListCredentialResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal status list credential JSON: %w", err)
	}

	return &result, nil
}

// IsRevoked checks whether a credential is revoked based on the encoded list
// and a given status position (index in the bitstring).
func IsRevoked(position int, subject StatusListCredentialSubject) (bool, error) {
	// Only handle revocation lists here.
	if subject.StatusPurpose != "revocation" {
		return false, nil
	}

	// Decode bitstring from encodedList.
	bits, err := DecodeEncodedList(subject.EncodedList)
	if err != nil {
		return false, err
	}

	if position < 0 || position >= len(bits) {
		return false, fmt.Errorf("status index %d out of range for bitstring of length %d", position, len(bits))
	}

	// Bit 1 at the position means revoked.
	return bits[position] == 1, nil
}

// DecodeEncodedList decodes the gzip+base64url encoded bitstring from
// StatusListCredentialSubject.EncodedList into a slice of bits (0 or 1).
func DecodeEncodedList(encodedList string) ([]int, error) {
	if encodedList == "" {
		return nil, fmt.Errorf("encodedList is empty")
	}

	// Decode and decompress from base64 URL encoding.
	data, err := util.DecompressFromBase64URL(encodedList)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress encodedList: %w", err)
	}

	var bits []int
	for _, b := range data {
		// Interpret each byte as 8 bits, least significant bit first,
		// to match status[position/8] & (1 << (position%8)) in storage.
		for i := 0; i < 8; i++ {
			if (b>>uint(i))&1 == 1 {
				bits = append(bits, 1)
			} else {
				bits = append(bits, 0)
			}
		}
	}

	return bits, nil
}
