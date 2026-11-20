package credentialstatus

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/pilacorp/go-credential-sdk/credential/common/jsonmap"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/internal/safehttp"
	"github.com/pilacorp/go-credential-sdk/credential/internal/vcdm"
)

const (
	// maxResponseBodySize is the maximum HTTP response body size when fetching
	// a status list credential (16 MiB). This limits the compressed payload
	// before any decompression.
	maxResponseBodySize int64 = 16 << 20

	// maxDecompressedSize is the upper bound on a decompressed bitstring
	// (16 MiB). This guards against decompression bombs while staying well
	// above the W3C 16 KB minimum.
	maxDecompressedSize int64 = 16 << 20
)

// defaultHTTPClient refuses connections to non-public addresses (loopback,
// RFC 1918, link-local, etc.) the same way the @context document loader does.
// Tests that need to reach httptest servers on 127.0.0.1 must pass
// WithHTTPClient to supply a client without the restriction.
var defaultHTTPClient = newDefaultHTTPClient()

// newDefaultHTTPClient bounds the whole request, body read included, at 10
// seconds: the public-only transport bounds only the dial and the handshake.
func newDefaultHTTPClient() *http.Client {
	c := safehttp.NewPublicOnlyClient()
	c.Timeout = 10 * time.Second
	return c
}

type Client struct {
	client   *http.Client
	resolver verificationmethod.ResolverProvider
}

type Option func(*Client)

func WithHTTPClient(client *http.Client) Option {
	return func(c *Client) {
		if client == nil {
			return
		}

		c.client = client
	}
}

// WithResolver sets the DID resolver used to verify the status list
// credential's proof. A non-nil resolver is required for
// VerifyAndCheckStatus; passing nil (or omitting the option) causes
// VerifyAndCheckStatus to return an error. The deprecated
// FetchAndCheckRevocation path does not require a resolver.
func WithResolver(resolver verificationmethod.ResolverProvider) Option {
	return func(c *Client) {
		c.resolver = resolver
	}
}

// SetDefaultHTTPClient replaces the package-level HTTP client used by
// NewClient when no WithHTTPClient option is passed. It exists so that tests
// running httptest servers on 127.0.0.1 can bypass the SSRF-safe dialer,
// the same way the @context loader's SetDocumentLoaderHTTPClient does.
// Passing nil restores the SSRF-safe default.
func SetDefaultHTTPClient(c *http.Client) {
	if c == nil {
		c = newDefaultHTTPClient()
	}
	defaultHTTPClient = c
}

func NewClient(options ...Option) *Client {
	client := &Client{
		client: defaultHTTPClient,
	}

	for _, option := range options {
		option(client)
	}

	return client
}

// FetchAndCheckRevocation fetches the status list credential from the given
// statusListCredential URL and checks whether the credential at the given
// position is revoked.
//
// Deprecated: use Client.VerifyAndCheckStatus which also verifies the status
// list credential's proof, issuer and validity period.
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

	resp, err := c.client.Get(statusListCredentialURL)
	if err != nil {
		return nil, fmt.Errorf("failed to call status list credential endpoint: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status list credential API returned non-200 status: %s", resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodySize+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read status list credential response body: %w", err)
	}
	if int64(len(body)) > maxResponseBodySize {
		return nil, fmt.Errorf("status list response exceeds %d bytes", maxResponseBodySize)
	}

	var result StatusListCredentialResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal status list credential JSON: %w", err)
	}

	return &result, nil
}

// VerifyAndCheckStatus fetches the status list credential, verifies its proof,
// checks the issuer match, checks validity period, and then reads the bit at
// position. entryPurpose is the statusPurpose from the VC entry's
// credentialStatus; issuerDID is the issuer of the credential being checked.
//
// A resolver must be set via WithResolver; calling this method without one
// returns an error. The deprecated FetchAndCheckRevocation path does not
// require a resolver.
//
// The status list credential response must have the shape {"data": <VC>}, the
// format authen-service uses. The VC inside "data" is verified as a whole.
//
// The HTTP response body is capped at 16 MiB; decompressed bitstrings are
// capped at 16 MiB.
func (c *Client) VerifyAndCheckStatus(statusListCredentialURL string, position int, entryPurpose, issuerDID string) error {
	if c.resolver == nil {
		return fmt.Errorf("resolver is required for VerifyAndCheckStatus: use WithResolver when creating the client")
	}

	if statusListCredentialURL == "" {
		return fmt.Errorf("statusListCredential URL is empty")
	}

	resp, err := c.client.Get(statusListCredentialURL)
	if err != nil {
		return fmt.Errorf("failed to call status list credential endpoint: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status list credential API returned non-200 status: %s", resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodySize+1))
	if err != nil {
		return fmt.Errorf("failed to read status list credential response body: %w", err)
	}
	if int64(len(body)) > maxResponseBodySize {
		return fmt.Errorf("status list response exceeds %d bytes", maxResponseBodySize)
	}

	// Parse the wrapper to get the raw VC for proof verification.
	var wrapper struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &wrapper); err != nil {
		return fmt.Errorf("failed to unmarshal status list credential response: %w", err)
	}

	// Parse the VC into the structured type.
	var slCredential StatusListCredential
	if err := json.Unmarshal(wrapper.Data, &slCredential); err != nil {
		return fmt.Errorf("failed to unmarshal status list credential: %w", err)
	}

	// Verify the status list credential's proof.
	var vcMap jsonmap.JSONMap
	if err := json.Unmarshal(wrapper.Data, (*map[string]interface{})(&vcMap)); err != nil {
		return fmt.Errorf("failed to unmarshal status list credential for proof verification: %w", err)
	}
	ok, err := vcMap.VerifyProof(c.resolver, "")
	if err != nil {
		return fmt.Errorf("status list credential proof verification failed: %w", err)
	}
	if !ok {
		return fmt.Errorf("status list credential proof is invalid")
	}

	// Verify the issuer matches the credential being checked.
	if slCredential.Issuer.DID == "" {
		return fmt.Errorf("status list credential has no issuer")
	}
	if slCredential.Issuer.DID != issuerDID {
		return fmt.Errorf("status list credential issuer %q does not match credential issuer %q", slCredential.Issuer.DID, issuerDID)
	}

	// Verify that every proof was signed by the issuer: the DID in each
	// proof's verificationMethod must equal the status list issuer.
	// VerifyProof checks the cryptographic signature but does not compare
	// the signer DID with the issuer field, so a list signed by a
	// different DID that has assertionMethod would pass without this.
	proofs, err := vcMap.Proofs()
	if err != nil {
		return fmt.Errorf("failed to parse status list credential proofs: %w", err)
	}
	for i, p := range proofs {
		proofDID := didFromVM(p.VerificationMethod)
		if proofDID == "" {
			return fmt.Errorf("status list credential proof %d has no DID in verificationMethod %q", i, p.VerificationMethod)
		}
		if proofDID != slCredential.Issuer.DID {
			return fmt.Errorf("status list credential proof %d signed by %q, but issuer is %q", i, proofDID, slCredential.Issuer.DID)
		}
	}

	// Verify validity period.
	if err := vcdm.CheckValidityPeriod("status list credential", slCredential.ValidFrom, slCredential.ValidUntil, 0); err != nil {
		return err
	}

	// Check the bit.
	isSet, err := CheckBitStatus(position, slCredential.CredentialSubject, entryPurpose)
	if err != nil {
		return err
	}
	if isSet {
		return fmt.Errorf("credential status is set for purpose %q", entryPurpose)
	}

	return nil
}

// CheckBitStatus checks whether the bit at position in the encoded bitstring
// is set. It detects the encoding from the encodedList value:
//
//   - W3C Bitstring Status List: encodedList starts with the multibase prefix
//     "u" (base64url-no-pad). After stripping the prefix, the value is
//     base64url-decoded, then gunzipped. Index 0 is the most significant bit of
//     byte 0 (MSB-first). The uncompressed bitstring must be at least 16 KB
//     (16384 bytes / 131072 bits).
//
//   - Legacy (authen-service): encodedList has no multibase prefix. It is a raw
//     base64url-no-pad encoding of gzipped bytes. Index 0 is the least
//     significant bit of byte 0 (LSB-first). No minimum size is enforced.
//
// Detection rule: gzip output encoded as base64url always starts with "H4sI"
// (the gzip magic bytes 0x1f 0x8b), so a legacy list never starts with "u".
// A "u" prefix therefore unambiguously marks the W3C multibase form.
//
// entryPurpose is the statusPurpose from the VC's credentialStatus entry.
// If subject.StatusPurpose does not match entryPurpose, an error is returned.
func CheckBitStatus(position int, subject StatusListCredentialSubject, entryPurpose string) (bool, error) {
	if subject.StatusPurpose != entryPurpose {
		return false, fmt.Errorf("statusPurpose mismatch: status list has %q, credential entry has %q", subject.StatusPurpose, entryPurpose)
	}

	encoded := subject.EncodedList
	if encoded == "" {
		return false, fmt.Errorf("encodedList is empty")
	}

	isW3C := strings.HasPrefix(encoded, "u")

	if isW3C {
		// W3C Bitstring Status List: strip the multibase 'u' prefix.
		raw := encoded[1:]
		byteString, err := decompressFromBase64URLWithLimit(raw, maxDecompressedSize)
		if err != nil {
			return false, fmt.Errorf("failed to decode W3C encodedList: %w", err)
		}
		// §2.2: the uncompressed bitstring MUST be at least 16 KB.
		if len(byteString) < 16384 {
			return false, fmt.Errorf("W3C bitstring status list must be at least 16 KB (131072 bits), got %d bytes (%d bits)", len(byteString), len(byteString)*8)
		}
		maxPosition := len(byteString)*8 - 1
		if position < 0 || position > maxPosition {
			return false, fmt.Errorf("position %d is out of range for bitstring of %d bits (max position: %d)", position, len(byteString)*8, maxPosition)
		}
		// MSB-first: index 0 is the most significant bit of byte 0.
		byteIndex := position / 8
		bitIndex := 7 - (position % 8)
		isSet := (byteString[byteIndex]>>uint(bitIndex))&1 == 1
		return isSet, nil
	}

	// Legacy form: base64url-no-pad of gzip data, LSB-first, no minimum size.
	byteString, err := decompressFromBase64URLWithLimit(encoded, maxDecompressedSize)
	if err != nil {
		return false, fmt.Errorf("failed to decode legacy encodedList: %w", err)
	}
	maxPosition := len(byteString)*8 - 1
	if position < 0 || position > maxPosition {
		return false, fmt.Errorf("position %d is out of range for bitstring of %d bits (max position: %d)", position, len(byteString)*8, maxPosition)
	}
	byteIndex := position / 8
	bitIndex := position % 8
	isSet := (byteString[byteIndex]>>uint(bitIndex))&1 == 1
	return isSet, nil
}

// IsRevoked checks whether a credential is revoked based on the encoded list
// and a given status position (index in the bitstring).
//
// Deprecated: use CheckBitStatus which handles both W3C and legacy encodings
// and compares the entry's statusPurpose. IsRevoked hard-codes the purpose to
// "revocation" and returns a statusPurpose mismatch error for any other purpose.
func IsRevoked(position int, subject StatusListCredentialSubject) (bool, error) {
	return CheckBitStatus(position, subject, "revocation")
}

// didFromVM extracts the DID prefix from a verification method URL
// ("did:x:y#key-1" -> "did:x:y"). Returns "" when vm is not a DID URL.
func didFromVM(vm string) string {
	if !strings.HasPrefix(vm, "did:") {
		return ""
	}
	if i := strings.IndexByte(vm, '#'); i > 0 {
		return vm[:i]
	}
	return vm
}

// decompressFromBase64URLWithLimit decodes a base64url-no-pad string, then
// gunzips it, capping the decompressed output at limit bytes to guard against
// decompression bombs.
func decompressFromBase64URLWithLimit(data string, limit int64) ([]byte, error) {
	compressed, err := base64.RawURLEncoding.DecodeString(data)
	if err != nil {
		return nil, err
	}
	gz, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, err
	}
	defer func() { _ = gz.Close() }()
	lr := io.LimitReader(gz, limit+1) // +1 to detect overflow
	out, err := io.ReadAll(lr)
	if err != nil {
		return nil, err
	}
	if int64(len(out)) > limit {
		return nil, fmt.Errorf("decompressed bitstring exceeds %d bytes", limit)
	}
	return out, nil
}
