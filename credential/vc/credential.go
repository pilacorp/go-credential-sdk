package vc

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/pilacorp/go-credential-sdk/credential/common/jsonmap"
	"github.com/pilacorp/go-credential-sdk/credential/common/processor"
	"github.com/pilacorp/go-credential-sdk/credential/common/sdjwt"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/internal/jwtutil"
)

// ErrSDJWTRequiresJOSE is returned when selective disclosure is asked of the VC
// 1.1 JWT path, which does not support it (#100): by NewJWTCredential given a
// WithSD* option or contents that already carry SD-JWT digests, by
// ParseJWTCredential given a token that carries SD-JWT machinery or arrives in
// the "~" combined form, and by JWTCredential.Present.
//
// SD-JWT over VC 1.1 was never a format anyone else could read: its header said
// typ "JWT", so a verifier outside this SDK had no way to know the token carried
// disclosures. Selective disclosure goes through vc+sd-jwt, the media type
// VC-JOSE-COSE defines for it: issue with NewJOSECredential, parse with
// ParseJOSECredential.
var ErrSDJWTRequiresJOSE = errors.New(
	"selective disclosure is supported only as vc+sd-jwt; use NewJOSECredential / ParseJOSECredential")

// ErrTooManyStatusLists is returned, wrapped with the counts, when a
// credential's credentialStatus names more status lists than
// WithMaxStatusLists allows.
var ErrTooManyStatusLists = errors.New("too many status lists")

// Config holds package configuration.
var config = struct {
	BaseURL string
}{
	BaseURL: "https://api.ndadid.vn/api/v1/did",
}

// Init initializes the package with a base URL.
func Init(baseURL string) {
	if baseURL != "" {
		config.BaseURL = baseURL
	}
}

// Credential is the consumer-facing contract: read, verify, and output. Signing
// and selective disclosure live on the concrete credential types.
type Credential interface {
	Verify(opts ...CredentialOpt) error
	// Serialize returns the JWT string (JWT) or the JSON object with proof (JSON).
	Serialize() (any, error)

	// Hash returns the SHA-256 hash (hex-encoded) of the full credential, including proof/signature.
	Hash() (string, error)

	GetContents() ([]byte, error)

	GetType() string

	// ExtractField returns a field by dot-notation path, or nil if absent.
	ExtractField(path string) any
}

// CredentialData represents credential data in JSON format (suitable for both JWT and JSON credentials).
type CredentialData jsonmap.JSONMap

// CredentialContents represents the structured contents of a Credential.
//
// RenderMethods is signed with the rest of the credential. With ecdsa-sd-2023,
// pass "/renderMethod" as a mandatory pointer, or the holder can drop or trim
// methods and the derived proof still verifies.
type CredentialContents struct {
	Context          []interface{}  `json:"context,omitempty"`          // JSON-LD contexts
	ID               string         `json:"id,omitempty"`               // Credential identifier
	Types            []string       `json:"type,omitempty"`             // Credential types
	Issuer           string         `json:"issuer,omitempty"`           // Issuer identifier
	ValidFrom        time.Time      `json:"validFrom,omitempty"`        // validFrom (VCDM 2.0); zero for a VCDM 1.1 credential
	ValidUntil       time.Time      `json:"validUntil,omitempty"`       // validUntil (VCDM 2.0); zero for a VCDM 1.1 credential
	CredentialStatus []Status       `json:"credentialStatus,omitempty"` // Credential status entries
	Subject          []Subject      `json:"subject,omitempty"`          // Credential subjects
	Schemas          []Schema       `json:"schemas,omitempty"`          // Credential schemas
	TermsOfUse       []TermsOfUse   `json:"termsOfUse,omitempty"`       // Terms of use policies
	RenderMethods    []RenderMethod `json:"renderMethod,omitempty"`     // W3C render methods
}

// Status represents the credentialStatus field as per W3C Verifiable Credentials.
type Status struct {
	ID                   string `json:"id,omitempty"`
	Type                 string `json:"type"`
	StatusPurpose        string `json:"statusPurpose,omitempty"`
	StatusListIndex      string `json:"statusListIndex,omitempty"`
	StatusListCredential string `json:"statusListCredential,omitempty"`
}

// Subject represents the credentialSubject field.
type Subject struct {
	ID           string                 `json:"id,omitempty"`           // Subject identifier
	CustomFields map[string]interface{} `json:"customFields,omitempty"` // Additional subject data
}

// Schema represents a credential schema with an ID and type.
type Schema struct {
	ID   string `json:"id,omitempty"`   // Schema identifier
	Type string `json:"type,omitempty"` // Schema type
}

// TermsOfUse represents a termsOfUse entry as per W3C Verifiable Credentials.
type TermsOfUse struct {
	ID   string `json:"id,omitempty"` // Policy identifier
	Type string `json:"type"`         // Policy type
}

// Decoy specifies where and how many decoy digests to add for SD-JWT privacy.
type Decoy = sdjwt.DecoyConfig

// SchemaLoaderFunc defines a function that loads a credential schema JSON by ID.
// It should return the raw JSON bytes for the schema corresponding to the given ID.
type SchemaLoaderFunc func(schemaID string) ([]byte, error)

// CredentialOpt configures credential processing options.
//
// TODO(opts): one option type is reused across constructors, Parse, signing
// and verification, so some options are meaningless in some call sites and
// are silently ignored there (e.g. WithVerificationMethodKey on
// NewJSONCredential, which only signing reads). Splitting into per-operation
// option sets is planned; until then each option documents where it applies.
// On the signing calls a verify-only option is ignored. JWT signing refuses the
// options only the constructors apply: kid (NewJWTCredential,
// NewJOSECredential) and SD-JWT (NewJOSECredential); AddCustomProof refuses
// the ones already inside the signed proof. JSON-LD AddProofByProvider applies
// the kid.
type CredentialOpt func(*credentialOptions)

// credentialOptions holds configuration for credential processing.
type credentialOptions struct {
	isValidateSchema        bool
	isVerifyProof           bool
	isCheckExpiration       bool
	leeway                  time.Duration
	isCheckRevocation       bool
	acceptLegacyStatusList  bool
	didBaseURL              string
	verificationMethodKey   string
	sdDisclosures           []string
	sdSelectivePaths        []string
	sdAlg                   string
	sdShuffle               bool
	sdDecoys                []sdjwt.DecoyConfig
	loadedSchemaLoader      SchemaLoaderFunc
	resolver                verificationmethod.ResolverProvider
	proofVerificationMethod string
	// expectedProofPurpose overrides the assertionMethod a VC verifier expects.
	expectedProofPurpose string
	replaceProof         bool
	// maxProofs caps the proofs a JSON-LD credential may carry; 0 means no cap.
	maxProofs int
	// jsonldLimits bounds the JSON-LD work Verify lets a document cause.
	jsonldLimits processor.JSONLDLimits
	// maxStatusLists caps the status lists WithCheckRevocation fetches; 0 means no cap.
	maxStatusLists int
	// statusListIssuers maps a credential issuer to list issuers trusted for
	// its credentials besides itself.
	statusListIssuers map[string][]string
	// statusListHTTPClient fetches status lists; nil means the package default.
	statusListHTTPClient *http.Client
}

// WithReplaceProof (signing) lets a signing call replace a signature the
// credential already carries. Without it, signing something already signed is
// refused.
//
// A JWT holds one signature, so there is no way to add a second: the first is
// gone either way. The option exists so that losing it is a choice. The new
// signature differs from the old one even over identical claims (ECDSA draws a
// fresh nonce), so the token's bytes and its Hash() change with it — which
// matters wherever Hash() is a key, as it is for on-chain anchoring.
//
// JSON-LD credentials append proofs rather than replacing them, so their
// signing calls refuse the option instead of ignoring it.
func WithReplaceProof() CredentialOpt {
	return func(c *credentialOptions) {
		c.replaceProof = true
	}
}

// refuseOverwrite stops a JWT signing call from replacing a signature the
// credential already carries, unless the caller passed WithReplaceProof.
//
// Signing with a wrong key or on a parsed token (no key bound) already fails,
// because signingKey.Accept checks the fresh signature before it is stored.
// What went through in silence was the other case: signing again with the right
// key succeeded, and Hash() changed. Shared by the VC 1.1 JWT and the vc+jwt
// credential, which both hold exactly one signature.
func refuseOverwrite(current string, options *credentialOptions) error {
	if current == "" || options.replaceProof {
		return nil
	}
	return fmt.Errorf(
		"credential is already signed; signing again would replace that signature — pass WithReplaceProof to do so deliberately")
}

// refuseReplaceOnJSONLD stops WithReplaceProof from reaching a JSON-LD signing
// call. Those calls append to the proof set, so honouring the option would mean
// silently appending when the caller asked to replace. Refused rather than
// ignored: with several proofs in a set, "replace" has no settled meaning yet,
// and refusing now leaves room to define one later without breaking anyone.
func refuseReplaceOnJSONLD(options *credentialOptions) error {
	if !options.replaceProof {
		return nil
	}
	return fmt.Errorf(
		"WithReplaceProof does not apply to JSON-LD: proofs are appended to the proof set, not replaced; build a new credential without the proof to re-sign")
}

// hasSDOptions reports whether any SD-JWT option was set. Kept beside the
// fields so a new sd* field is added here too.
func (o *credentialOptions) hasSDOptions() bool {
	return len(o.sdDisclosures) > 0 || len(o.sdSelectivePaths) > 0 || o.sdAlg != "" || o.sdShuffle || len(o.sdDecoys) > 0
}

// WithExpectedProofPurpose tells Verify to expect this proof purpose instead of
// assertionMethod. Data Integrity 1.0 §4.4 requires the comparison: a proof
// that names another purpose is refused even when the key is granted that
// other purpose. An empty purpose leaves the default in place.
func WithExpectedProofPurpose(purpose string) CredentialOpt {
	return func(c *credentialOptions) {
		if purpose == "" {
			return
		}
		c.expectedProofPurpose = purpose
	}
}

// diProofPurpose is the purpose a VC verifier compares with proof.proofPurpose.
func (o *credentialOptions) diProofPurpose() string {
	if o.expectedProofPurpose != "" {
		return o.expectedProofPurpose
	}
	return "assertionMethod"
}

// WithProofVerificationMethod restricts proof verification to the single proof
// bound to the given verification method URL (e.g. "did:example:issuer#key-2").
// By default all proofs in the set must verify; with this option only the
// selected proof is checked.
func WithProofVerificationMethod(vm string) CredentialOpt {
	return func(c *credentialOptions) {
		c.proofVerificationMethod = vm
	}
}

// WithMaxProofs makes Verify refuse a JSON-LD credential that carries more
// than n proofs, before any DID is resolved. A verifier that serves untrusted
// callers sets the most proofs its credentials carry. The count is of the
// whole credential, also with WithProofVerificationMethod. The same cap
// applies to each status list credential that Verify fetches with
// WithCheckRevocation. n <= 0 leaves the proof sets unbounded, which is the
// default. A JWT credential holds one signature, so the cap applies to it only
// through its status lists.
func WithMaxProofs(n int) CredentialOpt {
	return func(c *credentialOptions) {
		c.maxProofs = n
	}
}

// WithBaseURL sets the DID base URL for credential processing.
func WithBaseURL(baseURL string) CredentialOpt {
	return func(c *credentialOptions) {
		c.didBaseURL = baseURL
	}
}

// WithVerificationMethodKey sets the verification method fragment used when
// signing — e.g. "key-2". When omitted, the SDK resolves the issuer DID and
// picks its only VM, or the latest active VM listed in the assertionMethod
// relationship array (authentication for VPs).
//
// The cryptosuite is chosen from the bound VM's key type. If the DID holds
// keys of DIFFERENT types (e.g. secp256k1 and RSA), you MUST pin the VM here:
// otherwise the selected VM's key type may not match your signer, producing a
// proof that fails verification.
//
// For JSON credentials pass it to AddProofByProvider / AddProof; the
// constructors and Parse functions ignore it (see the TODO on CredentialOpt).
// For JWT credentials pass it to NewJWTCredential, which builds the header
// from it; the JWT signing calls refuse it, since the kid is already fixed.
// AddCustomProof (JSON or JWT) refuses it too: the proof arrives signed.
func WithVerificationMethodKey(key string) CredentialOpt {
	return func(c *credentialOptions) {
		if key == "" {
			return
		}
		c.verificationMethodKey = key
	}
}

// WithSchemaValidation enables schema validation during credential parsing.
func WithSchemaValidation() CredentialOpt {
	return func(c *credentialOptions) {
		c.isValidateSchema = true
	}
}

// WithVerifyProof enables proof verification during credential parsing.
// Signing calls ignore it; to check a proof added with AddCustomProof, call
// Verify afterwards.
func WithVerifyProof() CredentialOpt {
	return func(c *credentialOptions) {
		c.isVerifyProof = true
	}
}

// WithCheckExpiration refuses a credential outside the validity period it
// states, at the current time widened by WithLeeway: validFrom/validUntil
// (VCDM 2.0 §4.9) and issuanceDate/expirationDate (VCDM 1.1 §4.6, §4.8), each
// when present and whatever @context says. A date member that is there but is
// not a date-time string, empty included, is an error; one without a time
// zone is read as UTC. For a JWT credential, and for the JWT of a
// JwtProof2020 proof, it also enforces nbf and exp (RFC 7519 §4.1.4,
// §4.1.5).
func WithCheckExpiration() CredentialOpt {
	return func(c *credentialOptions) {
		c.isCheckExpiration = true
	}
}

// WithLeeway tolerates clock skew between issuer and verifier: every time check
// against the current time — validFrom/validUntil, issuanceDate/expirationDate
// and the JWT nbf/exp claims —
// is widened by d on both sides. It turns no check on by itself. Zero, the
// default, compares exactly; a negative d counts as zero. It does not touch the
// revocation check, which compares iat with the time a key was revoked, not
// with the current time. A large d also keeps an expired credential usable for
// that long, so keep it to the skew you expect, usually seconds.
func WithLeeway(d time.Duration) CredentialOpt {
	return func(c *credentialOptions) {
		c.leeway = max(d, 0)
	}
}

// WithCheckRevocation makes Verify read each BitstringStatusListEntry and
// refuse the credential when its revocation or suspension bit is set. One
// status list is fetched and verified once, also when it serves several
// statusPurpose values (Bitstring Status List v1.0 §2.2, §3.2 step 5). A refresh
// entry's list is not read, since §2.1 says a refresh status "does not
// invalidate the verifiable credential". Any other purpose, message included,
// is refused: a message status carries an issuer-defined message this SDK
// does not read.
func WithCheckRevocation() CredentialOpt {
	return func(c *credentialOptions) {
		c.isCheckRevocation = true
	}
}

// WithLegacyStatusList lets WithCheckRevocation read authen-service's legacy
// status lists: an encodedList with no multibase prefix, least significant bit
// first. Without it such a list is refused, because Bitstring Status List v1.0
// requires the multibase base64url form. Pass it only while the issuer still
// serves legacy lists.
func WithLegacyStatusList() CredentialOpt {
	return func(c *credentialOptions) {
		c.acceptLegacyStatusList = true
	}
}

// WithMaxStatusLists makes WithCheckRevocation refuse a credential whose
// credentialStatus names more than n status lists, before any list is
// fetched; the error wraps ErrTooManyStatusLists. Lists are counted by URL:
// entries on one list share one fetch, whatever statusPurpose each names. A
// refresh entry is not counted, since its list is not read.
// Each list costs a fetch of up to 16 MiB and a proof check, so a verifier
// that serves untrusted callers sets the most lists its credentials name.
// n <= 0 leaves the number unbounded, which is the default.
func WithMaxStatusLists(n int) CredentialOpt {
	return func(c *credentialOptions) {
		c.maxStatusLists = n
	}
}

// WithStatusListIssuers makes WithCheckRevocation accept, for a credential
// issued by credentialIssuer, a status list issued by one of listIssuers as
// well as one issued by credentialIssuer itself. Bitstring Status List v1.0
// §2.2 lets the two differ and leaves the trust to the verifier. The trust is
// per credential issuer: a list authority named for one issuer vouches for no
// other issuer's credentials. Without the option only the credential's issuer
// is trusted. An empty credentialIssuer or list issuer is ignored.
func WithStatusListIssuers(credentialIssuer string, listIssuers ...string) CredentialOpt {
	return func(c *credentialOptions) {
		if c.statusListIssuers == nil {
			c.statusListIssuers = map[string][]string{}
		}
		c.statusListIssuers[credentialIssuer] = append(c.statusListIssuers[credentialIssuer], listIssuers...)
	}
}

// WithStatusListHTTPClient sets the HTTP client WithCheckRevocation fetches
// status lists with. Bitstring Status List v1.0 §3.2 says verifiers SHOULD
// cache retrieved lists and SHOULD use proxies; a client with a caching or
// proxying transport does both. It replaces the package default client,
// which refuses non-public addresses; start from
// credentialstatus.NewPublicOnlyHTTPClient and wrap its Transport to keep that
// rule. nil keeps the default.
func WithStatusListHTTPClient(client *http.Client) CredentialOpt {
	return func(c *credentialOptions) {
		c.statusListHTTPClient = client
	}
}

// WithSDDisclosures attaches disclosures the caller built itself. It is the
// advanced path: the caller runs sdjwt.BuildDisclosures, puts the processed
// claims — digests and all — into the contents it hands the builder, and passes
// the matching disclosures here.
//
// The builder validates rather than trusts. Every disclosure has to match a
// digest the payload actually carries, and RFC 9901 applies: a disclosure
// matching nothing is refused (§7.1 step 5); so is the same one twice, which
// a Holder may not send (§4) and every reader refuses; and so is a digest
// that appears twice (§4.1, §7.1 step 4).
// A mismatch fails at build time with "invalid SD-JWT disclosures" rather than
// producing a token this SDK's own parser would reject.
//
// Do not combine it with WithSDSelectivePaths for the same claim. Those paths
// make the builder generate its own digests with a fresh salt, which no
// previously built disclosure can match. Combined for other claims, the
// digests already in the contents are kept: build the digests and the
// disclosures with one hash, and pass WithSDHashAlgorithm with the value given
// to BuildDisclosuresInput.HashAlgorithm, or the build is refused.
//
// For the ordinary case, name the claims with WithSDSelectivePaths and let the
// builder do both halves. To re-assemble a stored credential, parse the token:
// ParseJOSECredential reads the disclosures from the string. To reveal a subset
// of a credential already issued, use JOSECredential.Present.
//
// Applies to NewJOSECredential only; NewJWTCredential refuses it with
// ErrSDJWTRequiresJOSE.
func WithSDDisclosures(disclosures []string) CredentialOpt {
	return func(c *credentialOptions) {
		c.sdDisclosures = disclosures
	}
}

// WithSDSelectivePaths declares which claims should be selectively disclosable.
// When provided, the SDK will use sdjwt.BuildDisclosures to construct SD-JWT structures
// during credential issuance.
//
// A path to, or inside, a property a verifier decides on is refused (vc-jose-
// cose (W3C REC 2026-10-13) §3.2.1, RFC 9901 §9.7), and so is a top-level
// path; see WithSDDecoyDigests for the list and the reason.
//
// Applies to NewJOSECredential only; NewJWTCredential refuses it with
// ErrSDJWTRequiresJOSE.
func WithSDSelectivePaths(paths []string) CredentialOpt {
	return func(c *credentialOptions) {
		c.sdSelectivePaths = paths
	}
}

// WithSDHashAlgorithm sets the hash algorithm for SD-JWT.
// Supported: sha-256, sha-384, sha-512. Empty string defaults to sha-256.
//
// Applies to NewJOSECredential only; NewJWTCredential refuses it with
// ErrSDJWTRequiresJOSE.
func WithSDHashAlgorithm(alg string) CredentialOpt {
	return func(c *credentialOptions) {
		c.sdAlg = alg
	}
}

// WithSDShuffle has no effect: every _sd array is sorted, which hides the
// order of the claims (RFC 9901 §4.2.4.1), and array decoys go at random
// positions.
//
// Deprecated: drop the option; it will be removed in a future release.
//
// Applies to NewJOSECredential only; NewJWTCredential refuses it with
// ErrSDJWTRequiresJOSE.
func WithSDShuffle(enabled bool) CredentialOpt {
	return func(c *credentialOptions) {
		c.sdShuffle = enabled
	}
}

// WithSDDecoyDigests adds decoy digests at specified parent paths to obscure the
// number of disclosed claims. Each Decoy specifies the path where decoy digests
// should be added and the count of decoys.
//
// The path names an object (decoys go into its _sd) or an array (decoys become
// placeholders at random positions); a path to an array element adds to that
// array, a path to any other value adds to the object holding it, and a path
// not in the credential is refused.
//
// The path must not be in, or be, one of the properties a verifier decides on
// (@context, type, issuer, the validity window, credentialStatus,
// credentialSchema, relatedResource, iss, exp, nbf, cnf, aud as a whole), and
// must not be the root: a root digest with no disclosure cannot be told from a
// withheld exp or nbf, which this builder does not write, so the credential
// would fail Verify (RFC 9901 §9.7).
//
// Example: WithSDDecoyDigests([]vc.Decoy{{Path: "credentialSubject", Count: 3}})
//
// Applies to NewJOSECredential only; NewJWTCredential refuses it with
// ErrSDJWTRequiresJOSE.
func WithSDDecoyDigests(decoys []Decoy) CredentialOpt {
	return func(c *credentialOptions) {
		c.sdDecoys = decoys
	}
}

// WithSchemaLoader allows callers to provide a custom schema loader function.
// This enables loading schemas from different sources (e.g., files, caches, or remote services).
// If no custom loader is provided, the SDK will fall back to its default behavior.
func WithSchemaLoader(loader SchemaLoaderFunc) CredentialOpt {
	return func(c *credentialOptions) {
		if loader == nil {
			return
		}
		c.loadedSchemaLoader = loader
	}
}

// WithResolver sets the resolver for credential verification.
func WithResolver(resolver verificationmethod.ResolverProvider) CredentialOpt {
	return func(c *credentialOptions) {
		c.resolver = resolver
	}
}

// WithJSONLDLimits bounds the JSON-LD work verifying a document can cause
// (processor.JSONLDLimits). MaxValues is checked on the JSON before any
// JSON-LD processing; MaxScopedContextUses is enforced by json-gold in the
// proof's canonicalization and the compacted-form check. A document over a
// limit is refused with processor.ErrTooManyValues or
// processor.ErrTooManyScopedContextUses.
//
// No limit is set by default. Applies to Verify and to Parse with
// WithVerifyProof; signing calls ignore it.
func WithJSONLDLimits(limits processor.JSONLDLimits) CredentialOpt {
	return func(c *credentialOptions) {
		c.jsonldLimits = limits
	}
}

// signingOptions returns opts for a signing call, minus proof verification:
// there is no signature to verify before signing, and the signing paths check
// the fresh signature against the verification method's key. The other
// options (schema, expiration, revocation) check the content, so they run
// before the signer is called. The three-index slice makes append allocate,
// so the caller's slice is never written to.
func signingOptions(opts []CredentialOpt) []CredentialOpt {
	return append(opts[:len(opts):len(opts)], func(c *credentialOptions) { c.isVerifyProof = false })
}

// getOptions returns the credential options.
func getOptions(opts ...CredentialOpt) *credentialOptions {
	options := &credentialOptions{
		isValidateSchema:   false,
		isVerifyProof:      false,
		isCheckExpiration:  false,
		isCheckRevocation:  false,
		didBaseURL:         config.BaseURL,
		loadedSchemaLoader: nil,
		resolver:           nil,
	}

	for _, opt := range opts {
		opt(options)
	}

	if options.resolver == nil {
		options.resolver = verificationmethod.NewHTTPResolver(options.didBaseURL)
	}

	return options
}

// ParseCredential parses a credential from various formats into a Credential.
func ParseCredential(rawCredential []byte, opts ...CredentialOpt) (Credential, error) {
	if len(rawCredential) == 0 {
		return nil, fmt.Errorf("JSON string is empty")
	}

	if isJSONCredential(rawCredential) {
		// Check for EnvelopedVerifiableCredential data URI per W3C VC 2.0 / vc-jose-cose.
		//
		// VCDM 2.0 §4.13 pairs the data: URI with the EnvelopedVerifiableCredential
		// type, and both halves are load-bearing: unwrapping on the id alone lets
		// any JSON borrow an id and be read as whatever that id points at, with its
		// own type, issuer and subject silently discarded.
		var peek map[string]interface{}
		if err := json.Unmarshal(rawCredential, &peek); err == nil {
			if idStr, ok := peek["id"].(string); ok {
				for _, prefix := range []string{
					"data:application/" + TypeVCJWT + ",",
					"data:application/" + TypeVCSDJWT + ",",
				} {
					if !strings.HasPrefix(idStr, prefix) {
						continue
					}
					if !hasType(peek["type"], TypeEnvelopedVC) {
						return nil, fmt.Errorf("credential carries a %s id but its type is not %s", prefix, TypeEnvelopedVC)
					}
					// Parse the token as vc-jose-cose rather than recursing through
					// ParseCredential: the envelope is defined to hold a vc+jwt, so
					// this refuses a VC 1.1 JWT hidden inside a v2 envelope, and
					// keeps the nesting to one level.
					return ParseJOSECredential(strings.TrimPrefix(idStr, prefix), opts...)
				}
			}
		}
		return ParseJSONCredential(rawCredential, opts...)
	}

	valStr := strings.TrimSpace(strings.Trim(string(rawCredential), "\""))
	if sdjwt.IsSDJWT(valStr) || isJWTCredential(valStr) {
		// Auto-detect vc-jose-cose (vc+jwt) vs legacy VC 1.1 JWT
		// Only the issuer-signed JWT's header routes, so nothing after the
		// first "~" is decoded here; the parser it routes to bounds the rest.
		baseJWT, _, _ := strings.Cut(valStr, "~")
		parts := strings.Split(baseJWT, ".")
		if len(parts) >= 2 {
			// The header decides the parser, so it is read by the rules every
			// parser reads it with: a duplicate typ must not route one way
			// and verify another.
			header, err := jwtutil.DecodeHeaderSegment(parts[0])
			if err != nil {
				return nil, fmt.Errorf("failed to parse credential: invalid JWT header: %w", err)
			}
			if typ, ok := header["typ"].(string); ok {
				// Both vc+jwt and vc+sd-jwt are vc-jose-cose; only the
				// securing mechanism differs, so both route here. A tilde
				// alone does not decide it: a VC 1.1 SD-JWT has the same
				// shape with typ "JWT" and its claims under vc. It goes to the
				// 1.1 path below, which refuses it with ErrSDJWTRequiresJOSE.
				// SD-JWT profiles other than vc+sd-jwt, such as the IETF SD-JWT
				// VC (dc+sd-jwt), are not read here; name the typ rather than
				// point at JOSE.
				if strings.HasSuffix(strings.ToLower(typ), "+sd-jwt") && !isJOSECredentialTyp(typ) {
					return nil, fmt.Errorf("failed to parse credential: unsupported SD-JWT typ %.64q: only vc+sd-jwt is read", typ)
				}
				if isJOSECredentialTyp(typ) {
					return ParseJOSECredential(valStr, opts...)
				}
			}
		}
		return ParseJWTCredential(valStr, opts...)
	}

	return nil, fmt.Errorf("failed to parse credential: not a valid JSON, SD-JWT, or JWT credential")
}

// ParseCredentialWithValidation parses a credential from various formats into a Credential with validation.
func ParseCredentialWithValidation(rawCredential []byte) (Credential, error) {
	return ParseCredential(rawCredential, WithSchemaValidation(), WithVerifyProof())
}

func isJSONCredential(rawCredential []byte) bool {
	if len(rawCredential) == 0 {
		return false
	}

	if !json.Valid(rawCredential) {
		return false
	}

	var jsonMap map[string]interface{}
	err := json.Unmarshal(rawCredential, &jsonMap)
	if err != nil {
		return false
	}

	return true
}

func isJWTCredential(valStr string) bool {
	valStr = strings.Trim(valStr, "\"")
	regex := `^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$`
	match, _ := regexp.MatchString(regex, valStr)
	return match
}
