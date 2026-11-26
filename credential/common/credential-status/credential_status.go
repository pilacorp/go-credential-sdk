package credentialstatus

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/pilacorp/go-credential-sdk/credential/common/jsonmap"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/internal/errtext"
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
	maxProofs        int
	// acceptedListIssuers maps a credential issuer to the list issuers trusted
	// for its credentials besides itself.
	acceptedListIssuers map[string]map[string]bool
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

// WithMaxProofs makes VerifyStatusList refuse a status list credential that
// carries more than n proofs, with an error wrapping jsonmap.ErrTooManyProofs,
// before any DID is resolved. n <= 0 leaves the proof set unbounded, which is
// the default.
func WithMaxProofs(n int) Option {
	return func(c *Client) { c.maxProofs = n }
}

// WithAcceptedListIssuers makes VerifyStatusList accept, for credentials
// issued by credentialIssuer, a status list issued by one of listIssuers as
// well as one issued by credentialIssuer itself. Bitstring Status List v1.0
// §2.2 lets the two issuers differ ("MAY be different") and leaves which list
// issuers to trust to the verifier. The trust is per credential issuer, so a
// list authority named for one issuer vouches for no other issuer's
// credentials. With no option only the credential's issuer is trusted. An
// empty credentialIssuer or list issuer is ignored.
func WithAcceptedListIssuers(credentialIssuer string, listIssuers ...string) Option {
	return func(c *Client) {
		if credentialIssuer == "" {
			return
		}
		if c.acceptedListIssuers == nil {
			c.acceptedListIssuers = map[string]map[string]bool{}
		}
		set := c.acceptedListIssuers[credentialIssuer]
		if set == nil {
			set = map[string]bool{}
			c.acceptedListIssuers[credentialIssuer] = set
		}
		for _, d := range listIssuers {
			if d != "" {
				set[d] = true
			}
		}
	}
}

// NewPublicOnlyHTTPClient returns a client like the package default: it
// refuses connections to non-public addresses (loopback, RFC 1918,
// link-local, ...) and bounds each request at 10 seconds. A caller that wants
// a caching or proxying client wraps its Transport and keeps the address rule.
func NewPublicOnlyHTTPClient() *http.Client { return newDefaultHTTPClient() }

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
		return nil, withKind(ErrMalformedValue, fmt.Errorf("statusListCredential URL is empty"))
	}

	body, err := c.fetchStatusListBody(statusListCredentialURL)
	if err != nil {
		return nil, withKind(ErrStatusRetrieval, err)
	}

	var result StatusListCredentialResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, withKind(ErrStatusRetrieval, fmt.Errorf("failed to unmarshal status list credential JSON: %w", err))
	}

	return &result, nil
}

// fetchStatusListBody fetches the status list credential body from the given
// URL. The HTTP response body is capped at maxResponseBodySize.
func (c *Client) fetchStatusListBody(url string) ([]byte, error) {
	resp, err := c.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to call status list credential endpoint: %w", clippedError{err})
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status list credential API returned non-200 status: %s", errtext.Clip(resp.Status))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodySize+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read status list credential response body: %w", err)
	}
	if int64(len(body)) > maxResponseBodySize {
		return nil, fmt.Errorf("%w: status list response exceeds %d bytes", ErrStatusListTooLarge, maxResponseBodySize)
	}
	return body, nil
}

// clippedError prints its error clipped and unwraps to it, so a long URL,
// scheme or host from the credential, which *url.Error and its causes print
// in full, stays bounded while errors.As still finds *url.Error and the
// net.Error under it.
type clippedError struct{ err error }

func (e clippedError) Error() string {
	var ue *neturl.Error
	if errors.As(e.err, &ue) {
		return fmt.Sprintf("%s %q: %s", ue.Op, errtext.Clip(ue.URL), errtext.Clip(ue.Err.Error()))
	}
	return errtext.Clip(e.err.Error())
}
func (e clippedError) Unwrap() error { return e.err }

// VerifyAndCheckStatus fetches the status list credential, checks its types,
// statusPurpose, issuer and validity period, verifies its proof, and then
// reads the bit at position. entryPurpose is the statusPurpose from the VC entry's
// credentialStatus; issuerDID is the issuer of the credential being checked.
// Only revocation and suspension are read; any other entryPurpose is refused
// before the fetch. vc.Verify skips refresh entries itself.
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
	list, err := c.VerifyStatusList(statusListCredentialURL, entryPurpose, issuerDID)
	if err != nil {
		return err
	}
	return list.Check(position)
}

// StatusList is a status list credential that VerifyStatusList fetched and
// checked for one statusPurpose. IsSet reads its bits without fetching or
// verifying it again, so a credential with several entries on one list
// costs one fetch and one proof check. ForPurpose reuses it for another
// purpose the list also serves.
type StatusList struct {
	purpose  string
	purposes purposeSet // what the list's statusPurpose holds
	bits     []byte
	msbFirst bool // the W3C form; the authen-service legacy form is LSB-first
}

// ForPurpose returns the list for another statusPurpose it serves, without
// fetching or verifying it again. Bitstring Status List v1.0 §2.2 lets a
// list's statusPurpose be one or more strings, and §3.2 step 5 accepts an
// entry whose purpose is one of them (example: Appendix A.4).
func (l *StatusList) ForPurpose(purpose string) (*StatusList, error) {
	if l == nil {
		return nil, fmt.Errorf("status list is nil")
	}
	if err := checkSupportedPurpose(purpose); err != nil {
		return nil, err
	}
	if !l.purposes.serves(purpose) {
		return nil, withKind(ErrStatusVerification, l.purposes.mismatch(purpose))
	}
	out := *l
	out.purpose = purpose
	return &out, nil
}

// purposeSet records a list's statusPurpose in constant space: whether it
// serves each purpose this reader reads, the first few values for error text,
// and how many there are. A list can carry millions of purposes, and every
// entry on it asks whether it serves one.
type purposeSet struct {
	revocation, suspension bool
	shown                  []string // the first purposesShown values, clipped
	total                  int
}

const purposesShown = 4

func (p *purposeSet) add(purpose string) {
	switch purpose {
	case "revocation":
		p.revocation = true
	case "suspension":
		p.suspension = true
	}
	if len(p.shown) < purposesShown {
		p.shown = append(p.shown, errtext.Clip(purpose))
	}
	p.total++
}

func (p purposeSet) serves(purpose string) bool {
	switch purpose {
	case "revocation":
		return p.revocation
	case "suspension":
		return p.suspension
	}
	return false
}

// mismatch reports a list that does not serve the entry's purpose, in text
// bounded whatever the list holds.
func (p purposeSet) mismatch(entryPurpose string) error {
	more := ""
	if p.total > len(p.shown) {
		more = fmt.Sprintf(" and %d more", p.total-len(p.shown))
	}
	return fmt.Errorf("statusPurpose mismatch: status list serves %q%s, credential entry has %q", p.shown, more, errtext.Clip(entryPurpose))
}

// checkSupportedPurpose refuses a statusPurpose this reader does not check.
func checkSupportedPurpose(purpose string) error {
	switch purpose {
	case "revocation", "suspension":
		return nil
	}
	return fmt.Errorf("%w: statusPurpose %q is not supported: only revocation and suspension are", ErrUnsupported, errtext.Clip(purpose))
}

// VerifyStatusList does every step of VerifyAndCheckStatus except reading a
// bit: it fetches the status list credential, checks its types, statusPurpose
// against entryPurpose, issuer against issuerDID and validity period, verifies
// its proof, and decodes its bitstring.
func (c *Client) VerifyStatusList(statusListCredentialURL, entryPurpose, issuerDID string) (*StatusList, error) {
	if c.resolver == nil {
		return nil, fmt.Errorf("resolver is required for VerifyAndCheckStatus: use WithResolver when creating the client")
	}

	// Refuse unsupported purposes before fetching.
	if err := checkSupportedPurpose(entryPurpose); err != nil {
		return nil, err
	}

	if statusListCredentialURL == "" {
		return nil, withKind(ErrMalformedValue, fmt.Errorf("statusListCredential URL is empty"))
	}

	body, err := c.fetchStatusListBody(statusListCredentialURL)
	if err != nil {
		return nil, withKind(ErrStatusRetrieval, err)
	}

	// Accept the credential served as is, or wrapped as {"data": <credential>}.
	vcMap, err := statusListFromBody(body)
	if err != nil {
		return nil, withKind(ErrStatusRetrieval, err)
	}
	// Count the proofs before any of them is parsed: an oversized set is
	// refused at the cost of the body decode alone.
	if err := vcMap.CheckProofCount(c.maxProofs); err != nil {
		return nil, withKind(ErrStatusVerification, fmt.Errorf("status list credential proof verification failed: %w", err))
	}

	// Read status fields from the map whose proof is verified below, not from a
	// separate struct decode that could read case-variant sibling keys the proof
	// did not cover. The field checks run first because they cost nothing,
	// while the proof check canonicalizes the list and resolves a DID: a list
	// refused by a field check costs no DID resolution, and only the
	// credential's issuer or a DID trusted for it is ever resolved (see the
	// error kinds in errors.go).
	sl, err := c.checkListFields(vcMap, entryPurpose, issuerDID)
	if err != nil {
		return nil, err
	}
	if err := c.verifyListProofs(vcMap); err != nil {
		return nil, err
	}

	bits, msbFirst, err := decodeBitstring(sl.subject.EncodedList)
	if err != nil {
		return nil, err
	}
	return &StatusList{purpose: entryPurpose, purposes: sl.purposes, bits: bits, msbFirst: msbFirst}, nil
}

// checkListFields reads the list's status fields and runs every check on
// them that needs no proof, returning the view and the first failure.
func (c *Client) checkListFields(vcMap jsonmap.JSONMap, entryPurpose, issuerDID string) (statusListView, error) {
	sl, err := readStatusList(vcMap, entryPurpose)
	if err != nil {
		return sl, withKind(ErrMalformedValue, err)
	}
	// §3.2 step 5: the list must serve the entry's purpose.
	if sl.subject.StatusPurpose != entryPurpose {
		return sl, withKind(ErrStatusVerification, sl.purposes.mismatch(entryPurpose))
	}
	if sl.subject.EncodedList == "" {
		return sl, withKind(ErrMalformedValue, fmt.Errorf("encodedList is empty"))
	}
	// The list's issuer must be one this verifier trusts for the credential:
	// its issuer, or one WithAcceptedListIssuers names. §2.2 lets the two
	// differ and leaves the trust to the verifier.
	if sl.issuerDID == "" {
		return sl, withKind(ErrMalformedValue, fmt.Errorf("status list credential has no issuer"))
	}
	if issuerDID == "" {
		return sl, withKind(ErrStatusVerification, fmt.Errorf("the credential has no issuer DID to match the status list issuer against"))
	}
	if sl.issuerDID != issuerDID && !c.acceptedListIssuers[issuerDID][sl.issuerDID] {
		return sl, withKind(ErrStatusVerification, fmt.Errorf("status list credential issuer %q is neither the credential issuer %q nor one WithAcceptedListIssuers names for it", errtext.Clip(sl.issuerDID), errtext.Clip(issuerDID)))
	}
	// Every proof must be signed by the list's issuer: a proof by another DID
	// verifies only that DID's statement. Checked here, before any DID is
	// resolved; a failure is a §3.2 step 4 STATUS_VERIFICATION_ERROR.
	proofs, err := vcMap.Proofs()
	if err != nil {
		return sl, withKind(ErrStatusVerification, fmt.Errorf("failed to parse status list credential proofs: %w", err))
	}
	for i, p := range proofs {
		proofDID := didFromVM(p.VerificationMethod)
		if proofDID == "" {
			return sl, withKind(ErrStatusVerification, fmt.Errorf("status list credential proof %d has no DID in verificationMethod %q", i, errtext.Clip(p.VerificationMethod)))
		}
		if proofDID != sl.issuerDID {
			return sl, withKind(ErrStatusVerification, fmt.Errorf("status list credential proof %d signed by %q, but issuer is %q", i, errtext.Clip(proofDID), errtext.Clip(sl.issuerDID)))
		}
	}
	// Validity period, allowing for clock drift between the list's issuer,
	// which stamps validFrom when it serves the list, and this verifier: with
	// no leeway a verifier a second behind refused a fresh list.
	if err := vcdm.CheckValidity("status list credential", vcMap, statusListClockSkew); err != nil {
		return sl, withKind(ErrStatusVerification, err)
	}
	if err := vcMap.CheckJwtProofTimes(statusListClockSkew); err != nil {
		return sl, withKind(ErrStatusVerification, err)
	}
	// Refuse legacy lists unless the caller opted in.
	if !strings.HasPrefix(sl.subject.EncodedList, "u") && !c.acceptLegacyList {
		return sl, withKind(ErrMalformedValue, fmt.Errorf("status list encodedList is not multibase base64url; pass WithLegacyStatusList to read authen-service legacy lists"))
	}
	return sl, nil
}

// verifyListProofs verifies every proof of the list (§3.2 step 4); a failure
// is a STATUS_VERIFICATION_ERROR.
func (c *Client) verifyListProofs(vcMap jsonmap.JSONMap) error {
	// The purpose vc.Verify expects of a credential's proof; Data Integrity
	// 1.0 §4.4 refuses a proof that names another purpose.
	ok, err := vcMap.VerifyProof(c.resolver, "", jsonmap.WithExpectedProofPurpose("assertionMethod"), jsonmap.WithMaxProofs(c.maxProofs))
	if err != nil {
		return withKind(ErrStatusVerification, fmt.Errorf("status list credential proof verification failed: %w", err))
	}
	if !ok {
		return withKind(ErrStatusVerification, fmt.Errorf("status list credential proof is invalid"))
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
	purposes  purposeSet
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
		sl.purposes.add(p)
	case []interface{}:
		if len(p) == 0 {
			return sl, fmt.Errorf("status list credentialSubject.statusPurpose must be one or more strings")
		}
		for _, v := range p {
			s, ok := v.(string)
			if !ok {
				return sl, fmt.Errorf("status list credentialSubject.statusPurpose must be one or more strings")
			}
			sl.purposes.add(s)
			if s == entryPurpose {
				sl.subject.StatusPurpose = entryPurpose
			}
		}
	default:
		return sl, fmt.Errorf("status list credentialSubject.statusPurpose must be one or more strings")
	}

	return sl, nil
}

// statusListClockSkew is the leeway on the status list credential's validity
// period. authen-service sets validFrom to its own clock, in whole seconds,
// each time it serves the list.
const statusListClockSkew = time.Minute

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
		var listPurpose purposeSet
		listPurpose.add(subject.StatusPurpose)
		return false, withKind(ErrStatusVerification, listPurpose.mismatch(entryPurpose))
	}
	bits, msbFirst, err := decodeBitstring(subject.EncodedList)
	if err != nil {
		return false, err
	}
	return (&StatusList{bits: bits, msbFirst: msbFirst}).IsSet(position)
}

// decodeBitstring decodes an encodedList in the form its prefix names (see
// CheckBitStatus) and reports whether its bits are read MSB-first.
func decodeBitstring(encoded string) ([]byte, bool, error) {
	if encoded == "" {
		return nil, false, withKind(ErrMalformedValue, fmt.Errorf("encodedList is empty"))
	}
	if strings.HasPrefix(encoded, "u") {
		// W3C Bitstring Status List: strip the multibase 'u' prefix.
		bits, err := decompressFromBase64URLWithLimit(encoded[1:], maxDecompressedSize)
		if err != nil {
			return nil, false, withKind(ErrMalformedValue, fmt.Errorf("failed to decode encodedList: %w", err))
		}
		// §2.2: the uncompressed bitstring MUST be at least 16 KB.
		if len(bits) < 16384 {
			return nil, false, withKind(ErrStatusListLength, fmt.Errorf("bitstring status list must be at least 16 KB (131072 bits), got %d bytes (%d bits)", len(bits), len(bits)*8))
		}
		return bits, true, nil
	}
	// Legacy form: base64url-no-pad of gzip data, LSB-first, no minimum size.
	bits, err := decompressFromBase64URLWithLimit(encoded, maxDecompressedSize)
	if err != nil {
		return nil, false, withKind(ErrMalformedValue, fmt.Errorf("failed to decode legacy encodedList: %w", err))
	}
	return bits, false, nil
}

// Check returns an error when the bit at position is set, naming the list's
// statusPurpose, or when position is out of range.
func (l *StatusList) Check(position int) error {
	isSet, err := l.IsSet(position)
	if err != nil {
		return err
	}
	if isSet {
		return fmt.Errorf("credential status is set for purpose %q", l.purpose)
	}
	return nil
}

// IsSet reports whether the bit at position is set.
func (l *StatusList) IsSet(position int) (bool, error) {
	maxPosition := len(l.bits)*8 - 1
	if position < 0 || position > maxPosition {
		return false, withKind(ErrRange, fmt.Errorf("position %d is out of range for bitstring of %d bits (max position: %d)", position, len(l.bits)*8, maxPosition))
	}
	byteIndex := position / 8
	bitIndex := position % 8
	if l.msbFirst {
		// MSB-first: index 0 is the most significant bit of byte 0.
		bitIndex = 7 - bitIndex
	}
	return (l.bits[byteIndex]>>uint(bitIndex))&1 == 1, nil
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
		return nil, fmt.Errorf("%w: decompressed bitstring exceeds %d bytes", ErrStatusListTooLarge, limit)
	}
	return out, nil
}
