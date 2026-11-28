package vc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/pilacorp/go-credential-sdk/credential/common/dto"
	"github.com/pilacorp/go-credential-sdk/credential/common/jsonmap"
	"github.com/pilacorp/go-credential-sdk/credential/common/processor"
	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/internal/compactform"
	"github.com/pilacorp/go-credential-sdk/credential/internal/errtext"
	"github.com/pilacorp/go-credential-sdk/credential/internal/vcdm"
)

type JSONCredential struct {
	credentialData CredentialData
}

var _ Credential = (*JSONCredential)(nil)

func NewJSONCredential(vcc CredentialContents, opts ...CredentialOpt) (*JSONCredential, error) {
	m, err := serializeCredentialContents(&vcc)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize credential contents: %w", err)
	}

	e := &JSONCredential{
		credentialData: m,
	}
	return e, e.executeOptions(opts...)
}

func ParseJSONCredential(rawJSON []byte, opts ...CredentialOpt) (*JSONCredential, error) {
	if !isJSONCredential(rawJSON) {
		return nil, fmt.Errorf("invalid JSON format")
	}

	if len(rawJSON) == 0 {
		return nil, fmt.Errorf("JSON string is empty")
	}

	var m CredentialData
	if err := json.Unmarshal(rawJSON, &m); err != nil {
		return nil, fmt.Errorf("failed to unmarshal credential: %w", err)
	}
	if err := requireCredentialProperties(m); err != nil {
		return nil, err
	}

	e := &JSONCredential{credentialData: m}

	return e, e.executeOptions(opts...)
}

// Required on every credential by VC Data Model 2.0 §4.3, §4.5, §4.7, §4.8.
var requiredCredentialProperties = []string{"@context", "type", "issuer", "credentialSubject"}

// requireCredentialProperties checks presence only; value rules like the v2
// @context URL would reject the VC 1.1 documents this SDK still signs.
func requireCredentialProperties(m CredentialData) error {
	for _, p := range requiredCredentialProperties {
		if isEmptyValue(m[p]) {
			return fmt.Errorf("credential is missing %s", p)
		}
	}
	return nil
}

// credentialsV2Context is the @context VC Data Model 2.0 §4.3 requires first on
// every credential. vc-jose-cose is defined against 2.0 only, so the JOSE paths
// hold documents to it; the VC 1.1 paths do not, and keep their own context.
const credentialsV2Context = "https://www.w3.org/ns/credentials/v2"

// requireJOSECredential checks a payload really is the VC 2.0 credential its
// vc+jwt media type claims: the properties every credential carries, the v2
// @context, and a type that names a credential rather than something else.
//
// Per vc-jose-cose § Validation the verified payload must be a well-formed
// credential; verifying the signature alone does not establish that.
func requireJOSECredential(m CredentialData) error {
	if err := requireCredentialProperties(m); err != nil {
		return err
	}
	if err := requireV2Context(m["@context"]); err != nil {
		return err
	}
	return requireCredentialType(m["type"])
}

// securedClaims are the payload properties a verifier decides on: what the
// credential is (@context, type), who issued it, when it is valid, where to
// look up revocation and which schema it follows (vc-jose-cose (W3C REC
// 2026-10-13) §3.2.1 names @context, type, credentialStatus, credentialSchema
// and relatedResource), plus the JWT claims RFC 9901 §9.7 calls security
// critical (iss, aud, exp, nbf, cnf). Both the 1.1 and the 2.0 spelling of the
// validity window are listed, whichever one a payload uses. The sources ask
// issuers not to conceal them (a SHOULD, over lists that are not closed);
// refusing a vc+sd-jwt that does is this SDK's policy as a verifier.
var securedClaims = []string{
	"@context", "type",
	"issuer", "iss",
	"validFrom", "validUntil",
	"issuanceDate", "expirationDate",
	"exp", "nbf",
	"credentialStatus", "credentialSchema", "relatedResource",
	"aud", "cnf",
}

// requireSecuredClaimsSigned refuses a token whose reconstruction introduced one
// of those properties.
//
// Selective disclosure moves a property outside the signature: it is the
// digest that is signed, and the value arrives separately, under the holder's
// control. For a claim nobody checks that is the point. For these claims it is
// not:
//
//   - Hiding issuer let an attacker sign with its own key and name itself in
//     iss — which matched, because the signed payload had no issuer to compare
//     against — and the credential handed back named the victim as issuer.
//   - Withholding the disclosure for expirationDate or credentialStatus made an
//     expired or revoked credential verify as neither, since the checks run on
//     the reconstructed payload and found nothing to check.
//
// A disclosure the holder attached can be named, and is refused here. One the
// holder withheld cannot: the digest left behind does not record what it stood
// for. A withheld issuer, @context or type leaves a payload that is not a
// credential; a withheld optional one is caught by requireClaimsNotWithheld
// when a check that reads it runs.
//
// A disclosed name that differs from one of them only by case is refused too:
// encoding/json matches struct fields case-insensitively, folding ſ to s, so a
// consumer decoding the contents would read "iſſuer" as issuer. vc and vp
// must not be present at all (vc-jose-cose §1.1.2.1), in any case.
func requireSecuredClaimsSigned(signed, reconstructed map[string]interface{}) error {
	added := make([]string, 0, len(reconstructed))
	for k := range reconstructed {
		if _, ok := signed[k]; !ok {
			added = append(added, k)
		}
	}
	sort.Strings(added) // the same input fails with the same error
	for _, k := range added {
		if strings.EqualFold(k, "vc") || strings.EqualFold(k, "vp") {
			return fmt.Errorf("%q was selectively disclosed; the JWT claim names vc and vp must not be present", k)
		}
		for _, claim := range securedClaims {
			switch {
			case k == claim:
				return fmt.Errorf(
					"%q was selectively disclosed; a verifier decides on it, so it must be part of the signed payload",
					claim)
			case strings.EqualFold(k, claim):
				return fmt.Errorf("disclosed claim %.64q differs from %q only by case; a consumer may read it as %s", k, claim, claim)
			}
		}
	}
	return nil
}

// requireSecuredClaimsNotConcealed refuses a vc+sd-jwt payload in which one of
// securedClaims holds concealed parts (an _sd array or a {"...": digest}
// array element), at any depth. Withholding them changes what the verifier
// decides on: an issuer that made every field of credentialStatus disclosable
// left a holder able to withhold all of them, and reconstruction produced
// credentialStatus: {}, which checkRevocation reads as "this credential does
// not use revocation". Concealed aud array entries are allowed, as RFC 9901
// §9.7 lets an issuer make them disclosable. Runs before Reconstruct, which removes the evidence.
//
// Every other property, the payload root included, may be concealed (RFC
// 9901 §4.2).
func requireSecuredClaimsNotConcealed(m map[string]interface{}) error {
	for _, name := range securedClaims {
		v, ok := m[name]
		if !ok {
			continue
		}
		if name == "aud" {
			v = audWithoutEntryPlaceholders(v)
		}
		if carriesSDMachinery(v) {
			return fmt.Errorf("selective disclosure is not permitted inside %q; a verifier decides on it, so all of it must be part of the signed payload", name)
		}
	}
	return nil
}

// audWithoutEntryPlaceholders drops the {"...": digest} entries of an aud
// array, which RFC 9901 §9.7 lets an issuer conceal; anything else stays to
// be checked, an aud object with _sd included.
func audWithoutEntryPlaceholders(v interface{}) interface{} {
	arr, ok := v.([]interface{})
	if !ok {
		return v
	}
	out := make([]interface{}, 0, len(arr))
	for _, el := range arr {
		if m, ok := el.(map[string]interface{}); ok && len(m) == 1 {
			if _, ok := m["..."]; ok {
				continue
			}
		}
		out = append(out, el)
	}
	return out
}

// carriesSDMachinery reports whether value holds anything the SD-JWT layer puts
// in a payload, at any depth: an _sd digest array, or the {"...": digest}
// placeholder that stands for a withheld array element.
//
// The placeholder is only looked for inside arrays, which is the only place
// RFC 9901 §4.2.4.2 defines it and the only
// place Reconstruct acts on it. A map value of that shape elsewhere reconstructs
// to nothing, so it is not machinery to refuse.
func carriesSDMachinery(value interface{}) bool {
	switch v := value.(type) {
	case map[string]interface{}:
		if _, ok := v["_sd"]; ok {
			return true
		}
		for _, child := range v {
			if carriesSDMachinery(child) {
				return true
			}
		}
	case []interface{}:
		for _, child := range v {
			if elem, ok := child.(map[string]interface{}); ok && len(elem) == 1 {
				if _, ok := elem["..."]; ok {
					return true
				}
			}
			if carriesSDMachinery(child) {
				return true
			}
		}
	}

	return false
}

// requireV2Context enforces VCDM 2.0 §4.3: the v2 URL comes first. The data
// model asks for an ordered set, but a lone string means the same thing and is
// accepted rather than turned into a second way to fail.
func requireV2Context(v interface{}) error {
	var first string
	switch t := v.(type) {
	case string:
		first = t
	case []interface{}:
		if len(t) > 0 {
			first, _ = t[0].(string)
		}
	}
	if first != credentialsV2Context {
		return fmt.Errorf("credential must name %q first in @context, got %.64q", credentialsV2Context, first)
	}
	return nil
}

// requireCredentialType keeps a presentation — or any other document — from
// being read as a credential just because the header said vc+jwt.
func requireCredentialType(v interface{}) error {
	if hasType(v, "VerifiableCredential") {
		return nil
	}
	return fmt.Errorf("credential type must include VerifiableCredential, got %q", errtext.Clip(fmt.Sprint(v)))
}

// hasType reports whether a type property names want. Shared with the vp package
// through internal/vcdm, because both decide the same thing about the same data
// model and two copies of that rule would drift.
func hasType(v interface{}, want string) bool {
	return vcdm.HasType(v, want)
}

// isEmptyValue treats absent, null, "" and empty arrays/objects alike.
func isEmptyValue(v interface{}) bool {
	switch t := v.(type) {
	case nil:
		return true
	case string:
		return t == ""
	case []interface{}:
		return len(t) == 0
	case map[string]interface{}:
		return len(t) == 0
	}
	return false
}

// AddProof signs with a raw P-256 private key (hex scalar).
//
// Deprecated: prefer AddProofByProvider, which keeps the key outside the SDK.
func (e *JSONCredential) AddProof(priv string, opts ...CredentialOpt) error {
	p256Signer, err := signer.NewP256ProviderFromHex(priv)
	if err != nil {
		return fmt.Errorf("failed to create P-256 signer: %w", err)
	}
	return e.AddProofByProvider(p256Signer, opts...)
}

// AddProofByProvider signs with a provider, bound to the VM
// WithVerificationMethodKey pins, or by default the issuer's only VM / latest
// active assertionMethod VM.
//
// The proof suite follows the verification method's key: a P-256 key produces
// an ecdsa-rdfc-2019 proof, a secp256k1 key an EcdsaSecp256k1Signature2019 one.
// The second suite needs its terms defined, so its @context is added to the
// document unless the document already defines them. RSA is rejected either
// way.
//
// A resolver is REQUIRED at signing time: the SDK reads the VM's key type from
// the resolved DID document. Provide one with WithResolver (a default HTTP
// resolver is used otherwise).
func (e *JSONCredential) AddProofByProvider(provider signer.SignerProvider, opts ...CredentialOpt) error {
	if provider == nil {
		return fmt.Errorf("signer provider cannot be nil")
	}
	if err := refuseReplaceOnJSONLD(getOptions(opts...)); err != nil {
		return err
	}

	if err := e.executeOptions(signingOptions(opts)...); err != nil {
		return err
	}
	// Verify refuses a credential whose JSON is not in compacted form, so the
	// SDK does not sign one.
	if err := e.verifyCompactedForm(processor.JSONLDLimits{}); err != nil {
		return fmt.Errorf("cannot sign: %w", err)
	}

	vm, vmURL, err := e.resolveSigningVMEntry(opts...)
	if err != nil {
		return err
	}

	kind, ok := verificationmethod.VMKeyKind(vm)
	if !ok {
		return fmt.Errorf("verification method %.64q has an unrecognized key type", vmURL)
	}

	suite, err := jsonmap.SigningSuiteForKey(kind)
	if err != nil {
		return err
	}

	vmPub, err := verificationmethod.ECPubFromVM(vm)
	if err != nil {
		return fmt.Errorf("verification method %.64q: %w", vmURL, err)
	}

	m := (*jsonmap.JSONMap)(&e.credentialData)

	if suite == jsonmap.EcdsaSecp256k1Signature2019 {
		return m.AddEcdsaSecp256k1Proof(
			provider, vmURL, "assertionMethod", jsonmap.WithVMPublicKey(vmPub))
	}
	return m.AddECDSAProof(
		provider, vmURL, "assertionMethod", jsonmap.WithVMPublicKey(vmPub))
}

// resolveSigningVMEntry resolves the verification method to sign with and
// returns the entry so the caller can read its key type and choose the
// cryptosuite. Shared with ECDSASDCredential.
func (e *JSONCredential) resolveSigningVMEntry(opts ...CredentialOpt) (*verificationmethod.VerificationMethodEntry, string, error) {
	issuer, ok := jsonmap.DIDFromField(e.credentialData["issuer"])
	if !ok {
		return nil, "", fmt.Errorf("issuer is missing or invalid")
	}

	options := getOptions(opts...)

	return verificationmethod.ResolveSigningVM(context.Background(), issuer, "assertionMethod", options.verificationMethodKey, options.resolver)
}

// GetSigningInput returns the SHA-256 digest of the canonicalized document
// body. For an ecdsa-rdfc-2019 proof, pass it to CreateProofSigning to obtain
// the digest the external signer signs.
func (e *JSONCredential) GetSigningInput() ([]byte, error) {
	return (*jsonmap.JSONMap)(&e.credentialData).DocumentDigest()
}

// CreateProofSigning returns the 32-byte digest the external signer signs:
// SHA-256 of the section 3.2.4 hashData built from docHash and the proof options.
func (e *JSONCredential) CreateProofSigning(docHash []byte, proof *dto.Proof) ([]byte, error) {
	hashData, err := (*jsonmap.JSONMap)(&e.credentialData).ProofHashData(docHash, proof)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(hashData)
	return digest[:], nil
}

// AddCustomProof attaches a proof signed outside the SDK, the last step of
// GetSigningInput → CreateProofSigning → sign → AddCustomProof.
//
// The proof is attached as given, apart from the proofValue encoding: this
// release issues base58btc ("z") values only, and the legacy hex form is
// refused.
//
// Pass WithVerifyProof to have the proof checked before it is attached: the DID
// in proof.verificationMethod is resolved and the signature checked against
// that key, so a proof signed over the wrong digest or by the wrong key fails
// here rather than at whoever receives the credential. It costs one DID
// resolution; without the option nothing is checked, as before. Only
// ecdsa-rdfc-2019 can be checked this way — see
// jsonmap.JSONMap.VerifyDetachedProof.
//
// A failed check leaves the credential exactly as it was.
func (e *JSONCredential) AddCustomProof(proof *dto.Proof, opts ...CredentialOpt) error {
	if proof == nil {
		return fmt.Errorf("proof cannot be nil")
	}
	if err := refuseReplaceOnJSONLD(getOptions(opts...)); err != nil {
		return err
	}

	if proof.Type == jsonmap.DataIntegrityProof && proof.Cryptosuite == jsonmap.ECDSARDFC2019 &&
		!strings.HasPrefix(proof.ProofValue, jsonmap.MultibaseBase58BTCPrefix) {
		return fmt.Errorf("proofValue must be multibase base58btc (%q prefix); hex proofs are no longer issued", jsonmap.MultibaseBase58BTCPrefix)
	}
	options := getOptions(opts...)
	// The proof arrives signed: its verificationMethod is part of the proof
	// configuration the signature covers, so an option cannot change it here.
	if options.verificationMethodKey != "" {
		return fmt.Errorf("WithVerificationMethodKey cannot be applied by AddCustomProof: set proof.VerificationMethod on the proof you sign")
	}

	m := (*jsonmap.JSONMap)(&e.credentialData)

	// Before the content options, because this is the question the caller just
	// asked by handing over a proof, and before attaching, so a proof that does
	// not check out leaves nothing behind.
	if options.isVerifyProof {
		if err := m.VerifyDetachedProof(options.resolver, proof, jsonmap.WithExpectedProofPurpose(options.diProofPurpose())); err != nil {
			return err
		}
	}

	if err := e.executeOptions(signingOptions(opts)...); err != nil {
		return err
	}
	if err := e.verifyCompactedForm(processor.JSONLDLimits{}); err != nil {
		return fmt.Errorf("cannot attach proof: %w", err)
	}

	return m.AddCustomProof(proof)
}

func (e *JSONCredential) Verify(opts ...CredentialOpt) error {
	opts = append(opts, WithVerifyProof())

	return e.executeOptions(opts...)
}

func (e *JSONCredential) Serialize() (any, error) {
	// Check if credential has proof
	if e.credentialData["proof"] == nil {
		return nil, fmt.Errorf("credential must have proof before serialization")
	}

	return (*jsonmap.JSONMap)(&e.credentialData).ToMap()
}

// Hash returns the SHA-256 hash (hex-encoded) of the JSON-LD canonicalized (URDNA2015)
// full credential, including the proof field — the identity of a signed
// credential (Merkle leaf). A multibase proof ("z" / "u", Data Integrity) is
// hashed with processor.Canonicalize; any other proof keeps CanonicalizeFull,
// so its digest changes only for the cases README lists under "Upgrading from
// piprate/json-gold". Only the first proof decides.
func (e *JSONCredential) Hash() (string, error) {
	if e.credentialData["proof"] == nil {
		return "", fmt.Errorf("credential must have proof before hashing")
	}
	m := (*jsonmap.JSONMap)(&e.credentialData)

	var digest []byte
	if m.HasMultibaseProof() {
		full, err := m.ToMap()
		if err != nil {
			return "", err
		}
		canonical, err := processor.Canonicalize(full)
		if err != nil {
			return "", fmt.Errorf("failed to canonicalize credential: %w", err)
		}
		sum := sha256.Sum256(canonical)
		digest = sum[:]
	} else {
		var err error
		if digest, err = m.CanonicalizeFull(); err != nil {
			return "", fmt.Errorf("failed to canonicalize credential: %w", err)
		}
	}

	return hex.EncodeToString(digest), nil
}

func (e *JSONCredential) GetContents() ([]byte, error) {
	return (*jsonmap.JSONMap)(&e.credentialData).ToJSON()
}

func (e *JSONCredential) GetType() string {
	return "JSON"
}

func (e *JSONCredential) ExtractField(path string) any {
	if e.credentialData == nil {
		return nil
	}
	return extractFieldFromMap(e.credentialData, path)
}

func (e *JSONCredential) executeOptions(opts ...CredentialOpt) error {
	options := getOptions(opts...)

	if options.isCheckRevocation && !options.isVerifyProof {
		return fmt.Errorf("credential verification failed: WithCheckRevocation requires WithVerifyProof — the credential's proof must be verified before fetching its status list")
	}

	// The value limit walks the JSON, before any JSON-LD processing; the
	// scoped-context limit goes to json-gold with the proof check below.
	// Limits protect the verifier, so signing calls skip them.
	if options.isVerifyProof {
		if err := processor.CheckJSONLDLimits(
			map[string]interface{}(e.credentialData), options.jsonldLimits); err != nil {
			return fmt.Errorf("credential verification failed: %w", err)
		}
	}

	// Count the proofs before schema validation and proof verification run.
	if options.isVerifyProof {
		if err := (*jsonmap.JSONMap)(&e.credentialData).CheckProofCount(options.maxProofs); err != nil {
			return fmt.Errorf("credential verification failed: verify proof: %w", err)
		}
	}

	// Step 1: verify the proof first. The proof check works on the canonical
	// RDF of the document, so it accepts any equivalent JSON shape. All later
	// checks read the raw JSON by key name, so they need the compacted form.
	if options.isVerifyProof {
		isValid, err := (*jsonmap.JSONMap)(&e.credentialData).VerifyProof(
			options.resolver,
			options.proofVerificationMethod,
			jsonmap.WithExpectedProofPurpose(options.diProofPurpose()),
			jsonmap.WithMaxProofs(options.maxProofs),
			jsonmap.WithJSONLDLimits(options.jsonldLimits),
		)
		if err != nil {
			return fmt.Errorf("credential verification failed: verify proof: %w", err)
		}
		if !isValid {
			return fmt.Errorf("credential verification failed: invalid proof")
		}

		// Step 2: the properties the SDK reads by name must say what the signed
		// document says (see vcCompactedForm). The raw data is not mutated.
		//
		// Only a proof over the canonical form lets the JSON-LD meaning differ
		// from what the keys say. A document secured only by JwtProof2020 is
		// not checked: the JWT binds its body key by key. That departs from
		// VC Data Model 2.0 §7.1 step 2, which names no securing mechanism.
		signsCanonical, err := (*jsonmap.JSONMap)(&e.credentialData).SignsCanonicalForm()
		if err != nil {
			return fmt.Errorf("credential verification failed: %w", err)
		}
		if signsCanonical {
			if err := e.verifyCompactedForm(options.jsonldLimits); err != nil {
				return fmt.Errorf("credential verification failed: %w", err)
			}
		}
	}

	// Step 3: the remaining checks read the credential by name, which step 2
	// proved says what the signed document says. Schema validation runs after
	// the proof, so an unsigned credential costs no schema fetch.
	if options.isValidateSchema {
		if err := validateCredential(e.credentialData, options); err != nil {
			return fmt.Errorf("credential verification failed: validate credential: %w", err)
		}
	}

	// Revocation check runs after the proof is verified: an unsigned or
	// forged credential must not trigger a GET to the statusListCredential
	// URL the attacker chose.
	if options.isCheckRevocation {
		if err := checkRevocation(e.credentialData, options); err != nil {
			return fmt.Errorf("credential verification failed: check revocation: %w", err)
		}
	}

	// checkExpiration always runs sequentially after parallel validations
	if options.isCheckExpiration {
		if err := checkExpiration(e.credentialData, options.leeway); err != nil {
			return fmt.Errorf("failed to check expiration: %w", err)
		}
		// The JWT of a JwtProof2020 proof is checked as the JWT path checks
		// it. Its body dates are not a substitute: a date at the claim's
		// second can lie later in that second, and a falsy exp (0) has no date.
		if err := (*jsonmap.JSONMap)(&e.credentialData).CheckJwtProofTimes(options.leeway); err != nil {
			return fmt.Errorf("failed to check expiration: %w", err)
		}
	}

	return nil
}

// vcCompactedForm lists the properties SDK checks and readers take from a
// credential by name: validity dates (VC Data Model 2.0 and 1.1), the issuer,
// and the nodes revocation, schema validation and rendering read.
var vcCompactedForm = compactform.Rules{
	Single:         []string{"issuer", "validFrom", "validUntil", "issuanceDate", "expirationDate"},
	Nodes:          []string{"issuer", "credentialSubject", "credentialStatus", "credentialSchema", "renderMethod"},
	NamedVCDMTerms: true,
}

// ErrNotCompactedForm is returned, wrapped with the property path, when the
// JSON of a JSON-LD document does not say what its signed meaning says for a
// property the SDK reads by name. It is processor.ErrNotCompactedForm.
var ErrNotCompactedForm = processor.ErrNotCompactedForm

// verifyCompactedForm refuses a credential whose JSON, for a property in
// vcCompactedForm, does not say what its signed meaning says. The raw data is
// never mutated.
func (e *JSONCredential) verifyCompactedForm(limits processor.JSONLDLimits) error {
	body, err := (*jsonmap.JSONMap)(&e.credentialData).ToMap()
	if err != nil {
		return fmt.Errorf("compact form check: serialize body: %w", err)
	}
	delete(body, "proof")
	return compactform.Check(body, vcCompactedForm, limits)
}
