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
	"sync/atomic"
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
var defaultHTTPClient atomic.Pointer[http.Client]

func init() { defaultHTTPClient.Store(newDefaultHTTPClient()) }

// newDefaultHTTPClient bounds the whole request, body read included, at 10
// seconds: the public-only transport bounds only the dial and the handshake.
func newDefaultHTTPClient() *http.Client {
	c := safehttp.NewPublicOnlyClient()
	c.Timeout = 10 * time.Second
	return c
}

type Client struct {
	client           *http.Client
	resolver         verificationmethod.ResolverProvider
	acceptLegacyList bool
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
	defaultHTTPClient.Store(c)
}

// WithLegacyStatusList lets VerifyAndCheckStatus read authen-service's
// legacy lists (no multibase prefix, least significant bit first).
func WithLegacyStatusList() Option {
	return func(c *Client) { c.acceptLegacyList = true }
}

func NewClient(options ...Option) *Client {
	client := &Client{
		client: defaultHTTPClient.Load(),
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

	body, err := c.fetchStatusListBody(statusListCredentialURL)
	if err != nil {
		return nil, err
	}

	var result StatusListCredentialResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal status list credential JSON: %w", err)
	}

	return &result, nil
}

// fetchStatusListBody fetches the status list credential body from the given
// URL. The HTTP response body is capped at maxResponseBodySize.
func (c *Client) fetchStatusListBody(url string) ([]byte, error) {
	resp, err := c.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to call status list credential endpoint: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
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
	return body, nil
}

// VerifyAndCheckStatus fetches the status list credential, checks its types,
// statusPurpose, issuer and validity period, verifies its proof, and then
// reads the bit at position. entryPurpose is the statusPurpose from the VC entry's
// credentialStatus; issuerDID is the issuer of the credential being checked.
//
// A resolver must be set via WithResolver; calling this method without one
// returns an error. The deprecated FetchAndCheckRevocation path does not
// require a resolver.
//
// The status list credential response may be served as the credential itself
// (has @context) or wrapped as {"data": <credential>} the way authen-service
// serves it.
//
// The HTTP response body is capped at 16 MiB; decompressed bitstrings are
// capped at 16 MiB.
func (c *Client) VerifyAndCheckStatus(statusListCredentialURL string, position int, entryPurpose, issuerDID string) error {
	if c.resolver == nil {
		return fmt.Errorf("resolver is required for VerifyAndCheckStatus: use WithResolver when creating the client")
	}

	// Refuse unsupported purposes before fetching.
	switch entryPurpose {
	case "revocation", "suspension":
	default:
		return fmt.Errorf("statusPurpose %q is not supported: only revocation and suspension are", entryPurpose)
	}

	if statusListCredentialURL == "" {
		return fmt.Errorf("statusListCredential URL is empty")
	}

	body, err := c.fetchStatusListBody(statusListCredentialURL)
	if err != nil {
		return err
	}

	// Accept the credential served as is, or wrapped as {"data": <credential>}.
	vcMap, err := statusListFromBody(body)
	if err != nil {
		return err
	}

	// Read status fields from the map whose proof is verified below, not from a
	// separate struct decode that could read case-variant sibling keys the proof
	// did not cover. The checks on them run first because they cost nothing,
	// while the proof check canonicalizes the list and resolves the issuer DID.
	sl, err := readStatusList(vcMap, entryPurpose)
	if err != nil {
		return err
	}

	// The list must serve the entry's purpose and carry a bitstring; both are
	// read again by CheckBitStatus, but checking here spares the proof check.
	if sl.subject.StatusPurpose != entryPurpose {
		return fmt.Errorf("statusPurpose mismatch: status list has %q, credential entry has %q", clip(sl.subject.StatusPurpose), clip(entryPurpose))
	}
	if sl.subject.EncodedList == "" {
		return fmt.Errorf("encodedList is empty")
	}

	// Verify the issuer matches the credential being checked.
	if sl.issuerDID == "" {
		return fmt.Errorf("status list credential has no issuer")
	}
	if sl.issuerDID != issuerDID {
		return fmt.Errorf("status list credential issuer %q does not match credential issuer %q", clip(sl.issuerDID), clip(issuerDID))
	}

	// Verify that every proof was signed by the issuer.
	proofs, err := vcMap.Proofs()
	if err != nil {
		return fmt.Errorf("failed to parse status list credential proofs: %w", err)
	}
	for i, p := range proofs {
		proofDID := didFromVM(p.VerificationMethod)
		if proofDID == "" {
			return fmt.Errorf("status list credential proof %d has no DID in verificationMethod %q", i, clip(p.VerificationMethod))
		}
		if proofDID != sl.issuerDID {
			return fmt.Errorf("status list credential proof %d signed by %q, but issuer is %q", i, clip(proofDID), clip(sl.issuerDID))
		}
	}

	// Verify validity period, allowing for clock drift between the list's
	// issuer, which stamps validFrom when it serves the list, and this
	// verifier: with no leeway a verifier a second behind refused a fresh list.
	if err := vcdm.CheckValidity("status list credential", vcMap, statusListClockSkew); err != nil {
		return err
	}
	if err := vcMap.CheckJwtProofTimes(statusListClockSkew); err != nil {
		return err
	}

	// Refuse legacy lists unless the caller opted in.
	if !strings.HasPrefix(sl.subject.EncodedList, "u") && !c.acceptLegacyList {
		return fmt.Errorf("status list encodedList is not multibase base64url; pass WithLegacyStatusList to read authen-service legacy lists")
	}

	// Verify the status list credential's proof for assertionMethod, the purpose
	// vc.Verify expects of a credential's proof; Data Integrity 1.0 §4.4 refuses
	// a proof that names another purpose.
	ok, err := vcMap.VerifyProof(c.resolver, "", jsonmap.WithExpectedProofPurpose("assertionMethod"))
	if err != nil {
		return fmt.Errorf("status list credential proof verification failed: %w", err)
	}
	if !ok {
		return fmt.Errorf("status list credential proof is invalid")
	}

	// Check the bit.
	isSet, err := CheckBitStatus(position, sl.subject, entryPurpose)
	if err != nil {
		return err
	}
	if isSet {
		return fmt.Errorf("credential status is set for purpose %q", entryPurpose)
	}

	return nil
}

// statusListFromBody accepts the status list credential served as is, or
// wrapped as {"data": <credential>} the way authen-service serves it.
func statusListFromBody(body []byte) (jsonmap.JSONMap, error) {
	var m map[string]interface{}
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("failed to unmarshal status list credential response: %w", err)
	}
	if _, isCredential := m["@context"]; isCredential {
		return jsonmap.JSONMap(m), nil
	}
	inner, ok := m["data"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf(`status list response must be a credential or {"data": <credential>}`)
	}
	return jsonmap.JSONMap(inner), nil
}

// statusListView holds the fields the status check reads, taken by exact key
// from the same map whose proof is verified.
type statusListView struct {
	issuerDID string
	subject   StatusListCredentialSubject
}

// readStatusList reads the status list fields from the map whose proof is
// verified after these fields are checked.
// It checks the credential type, credentialSubject.type, and reads the
// statusPurpose as a string or array per Bitstring Status List v1.0 §2.2.
func readStatusList(m jsonmap.JSONMap, entryPurpose string) (statusListView, error) {
	var sl statusListView

	// Check credential type (§2.1: MUST include BitstringStatusListCredential).
	if !vcdm.HasType(m["type"], "BitstringStatusListCredential") {
		return sl, fmt.Errorf("status list credential type must include BitstringStatusListCredential")
	}

	sl.issuerDID, _ = jsonmap.DIDFromField(m["issuer"])

	subject, ok := m["credentialSubject"].(map[string]interface{})
	if !ok {
		return sl, fmt.Errorf("status list credential has no credentialSubject object")
	}

	// Check credentialSubject.type (§2.2: MUST be BitstringStatusList).
	if !vcdm.HasType(subject["type"], "BitstringStatusList") {
		return sl, fmt.Errorf("status list credentialSubject.type must include BitstringStatusList")
	}

	sl.subject.EncodedList, _ = subject["encodedList"].(string)
	sl.subject.Type = "BitstringStatusList"

	// §2.2: statusPurpose MUST be one or more strings. Accept string or array.
	switch p := subject["statusPurpose"].(type) {
	case string:
		sl.subject.StatusPurpose = p
	case []interface{}:
		for _, v := range p {
			if s, ok := v.(string); ok && s == entryPurpose {
				sl.subject.StatusPurpose = entryPurpose
			}
		}
	}

	return sl, nil
}

// statusListClockSkew is the leeway on the status list credential's validity
// period. authen-service sets validFrom to its own clock, in whole seconds,
// each time it serves the list.
const statusListClockSkew = time.Minute

// clip truncates a string to at most 256 bytes for safe inclusion in error
// messages. Values echoed in errors come from the fetched list and are bounded
// only by the 16 MiB body limit.
func clip(s string) string {
	const max = 256
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
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
			return false, fmt.Errorf("failed to decode encodedList: %w", err)
		}
		// §2.2: the uncompressed bitstring MUST be at least 16 KB.
		if len(byteString) < 16384 {
			return false, fmt.Errorf("bitstring status list must be at least 16 KB (131072 bits), got %d bytes (%d bits)", len(byteString), len(byteString)*8)
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
