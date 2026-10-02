package vp

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/pilacorp/go-credential-sdk/credential/common/dto"
	"github.com/pilacorp/go-credential-sdk/credential/common/jsonmap"
	"github.com/pilacorp/go-credential-sdk/credential/common/jwt"
	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	"github.com/pilacorp/go-credential-sdk/credential/internal/jwtutil"
	"github.com/pilacorp/go-credential-sdk/credential/internal/vcdm"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
	"golang.org/x/sync/errgroup"
)

// JOSEPresentation implements W3C VC 2.0 Securing Verifiable Presentations using JOSE (vc-jose-cose).
// In vc-jose-cose, the unsecured Verifiable Presentation is the unencoded JWS payload (flat,
// without the legacy "vp" wrapper claim), and the header carries typ: "vp+jwt".
type JOSEPresentation struct {
	signingInput string           // JWS header.payload (base64 encoded)
	payloadData  PresentationData // Unsecured VP as PresentationData
	signature    string           // JWS signature (if signed)
	signingKey   jwt.SigningKey   // Verification method the header names; zero for a parsed presentation
}

var _ Presentation = (*JOSEPresentation)(nil)

// NewJOSEPresentation creates a new Verifiable Presentation secured with JOSE per W3C vc-jose-cose.
func NewJOSEPresentation(vpc PresentationContents, opts ...PresentationOpt) (*JOSEPresentation, error) {
	// Ensure W3C VC 2.0 context is present if no context specified
	if len(vpc.Context) == 0 {
		vpc.Context = []interface{}{"https://www.w3.org/ns/credentials/v2"}
	}

	m, err := serializePresentationContents(&vpc)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize presentation contents: %w", err)
	}

	payloadData := PresentationData(m)
	options := getOptions(opts...)

	// Refuse before signing what ParseJOSEPresentation would refuse after. The
	// caller's own @context survives the default above, so a v1 document used to
	// be signed under a vp+jwt label with nothing objecting.
	if err := requireJOSEPresentation(payloadData); err != nil {
		return nil, err
	}

	// Embedded credentials become EnvelopedVerifiableCredential entries, which
	// vc-jose-cose requires ("Verifiable Credentials secured in verifiable
	// presentations MUST use the Enveloped Verifiable Credential type"). Data
	// Integrity secures the document from the inside, so there is nothing to
	// envelope and no media type for it; those belong in a JSON presentation.
	if len(vpc.VerifiableCredentials) > 0 {
		envelopedList := make([]interface{}, len(vpc.VerifiableCredentials))
		for i, cred := range vpc.VerifiableCredentials {
			// No nil check here: serializePresentationContents ran above and
			// refuses both a nil interface and an interface holding a nil pointer,
			// so nothing nil reaches this loop.
			joseCred, ok := cred.(*vc.JOSECredential)
			if !ok {
				return nil, fmt.Errorf("credential at index %d is %T: a vp+jwt presentation can only carry "+
					"enveloping-secured credentials; use a JSON presentation for Data Integrity credentials", i, cred)
			}
			serialized, err := joseCred.Serialize()
			if err != nil {
				return nil, fmt.Errorf("failed to serialize credential at index %d: %w", i, err)
			}
			// The assertion cannot be skipped here: signingInput and signature
			// belong to vc.JOSECredential and are not reachable from this package.
			// Swallowing a failed assertion left credStr empty, and the error then
			// came out of envelopeMediaType as "credential is not signed" — right
			// by accident, about the wrong thing.
			credStr, ok := serialized.(string)
			if !ok {
				return nil, fmt.Errorf("credential at index %d serialized to %T, want a token string", i, serialized)
			}
			mediaType, err := envelopeMediaType(credStr)
			if err != nil {
				return nil, fmt.Errorf("credential at index %d: %w", i, err)
			}
			envelopedList[i] = map[string]interface{}{
				"@context": []interface{}{"https://www.w3.org/ns/credentials/v2"},
				"type":     []interface{}{vc.TypeEnvelopedVC},
				"id":       fmt.Sprintf("data:application/%s,%s", mediaType, credStr),
			}
		}
		payloadData["verifiableCredential"] = envelopedList
	}

	// Challenge/domain map to the standard JWT claims (nonce and aud)
	if options.challenge != "" {
		payloadData["nonce"] = options.challenge
	}
	if options.domain != "" {
		payloadData["aud"] = options.domain
	}

	// Per W3C vc-jose-cose Section 1.1.2.1:
	// "The JWT Claim Names vc and vp MUST NOT be present in any JWT Claims Set"
	delete(payloadData, "vc")
	delete(payloadData, "vp")

	// Without iat the verifier has no signing time to compare a soft revocation
	// against, and would have to guess one from validFrom — a different fact.
	jwtutil.SetIssuedAt(payloadData, time.Now())

	// Resolve the verification method the header will name, and keep it: every
	// signing path checks the signature it is handed against this key before
	// attaching it, so a signature made by another key fails here rather than at
	// whoever receives the presentation.
	signingKey, err := jwt.ResolveSigningKey(context.Background(), vpc.Holder,
		"authentication", options.verificationMethodKey, options.resolver)
	if err != nil {
		return nil, err
	}

	// Per W3C vc-jose-cose Section 3.1.2: typ MUST/SHOULD be "vp+jwt"
	header := map[string]interface{}{
		"typ": TypeVPJWT,
		"alg": signingKey.Alg,
		"kid": signingKey.ID,
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal header: %w", err)
	}
	headerEncoded := base64.RawURLEncoding.EncodeToString(headerJSON)

	payloadJSON, err := json.Marshal(payloadData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}
	payloadEncoded := base64.RawURLEncoding.EncodeToString(payloadJSON)

	signingInput := headerEncoded + "." + payloadEncoded

	e := &JOSEPresentation{
		signingInput: signingInput,
		payloadData:  payloadData,
		signature:    "",
		signingKey:   signingKey,
	}

	return e, e.executeOptions(opts...)
}

// ParseJOSEPresentation parses a W3C vc-jose-cose (vp+jwt) token.
func ParseJOSEPresentation(rawJWT string, opts ...PresentationOpt) (*JOSEPresentation, error) {
	rawJWT = strings.TrimSpace(strings.Trim(rawJWT, "\""))

	if !isJWTPresentation(rawJWT) {
		return nil, fmt.Errorf("invalid JWT format")
	}

	parts := strings.Split(rawJWT, ".")
	headerEncoded := parts[0]
	payloadEncoded := parts[1]
	signature := ""
	if len(parts) == 3 {
		signature = parts[2]
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(headerEncoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode header: %w", err)
	}
	var headerMap map[string]interface{}
	if err := json.Unmarshal(headerBytes, &headerMap); err != nil {
		return nil, fmt.Errorf("failed to unmarshal header: %w", err)
	}
	typ, _ := headerMap["typ"].(string)
	if !isJOSEPresentationTyp(typ) {
		return nil, fmt.Errorf("invalid typ header for JOSEPresentation: got %q, want %q", typ, TypeVPJWT)
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadEncoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}

	var payloadMap map[string]interface{}
	err = json.Unmarshal(payloadBytes, &payloadMap)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal payload: %w", err)
	}

	// Per W3C vc-jose-cose Section 1.1.2.1:
	// "The JWT Claim Names vc and vp MUST NOT be present in any JWT Claims Set"
	if _, hasVC := payloadMap["vc"]; hasVC {
		return nil, fmt.Errorf("invalid vc-jose-cose: 'vc' claim MUST NOT be present in payload")
	}
	if _, hasVP := payloadMap["vp"]; hasVP {
		return nil, fmt.Errorf("invalid vc-jose-cose: 'vp' claim MUST NOT be present in payload")
	}

	// Both checks run unconditionally. They decide whether this payload is a
	// well-formed vp+jwt at all, which is not something to gate behind
	// WithVCValidation — that option asks for the embedded credentials to be
	// verified, a different and far more expensive question.
	if err := requireJOSEPresentation(PresentationData(payloadMap)); err != nil {
		return nil, err
	}
	if err := requireEnvelopedCredentials(PresentationData(payloadMap)); err != nil {
		return nil, err
	}

	signingInput := headerEncoded + "." + payloadEncoded

	e := &JOSEPresentation{
		signingInput: signingInput,
		payloadData:  PresentationData(payloadMap),
		signature:    signature,
	}

	return e, e.executeOptions(opts...)
}

// TypeVPJWT is the media type vc-jose-cose gives a presentation secured with
// JWS, named by the typ header. The full "application/" spelling means the same
// and is accepted when reading.
const TypeVPJWT = "vp+jwt"

// TypeJOSE is what GetType reports for a presentation secured with
// vc-jose-cose. Exported for the same reason as its credential counterpart:
// consumers branch on the value.
const TypeJOSE = "JOSE"

// typeVerifiablePresentation is the type every presentation names, whatever else
// it adds alongside.
const typeVerifiablePresentation = "VerifiablePresentation"

// isJOSEPresentationTyp reports whether typ names a presentation secured the
// way vc-jose-cose defines, in either media type spelling.
//
// jwt.purposeFromTyp has to recognise every value accepted here, or a token this
// function routes would have its kind decided by its own payload. Adding one
// means adding it there.
func isJOSEPresentationTyp(typ string) bool {
	return typ == TypeVPJWT || typ == "application/"+TypeVPJWT
}

// requireJOSEPresentation checks the payload really is the VC 2.0 presentation
// its vp+jwt media type claims.
//
// A signature proves who produced the bytes, not what the bytes are, and
// vc-jose-cose § Validation requires the document handed back after verification
// to be a well-formed VCDM 2.0 document. Without this a payload of
// {"holder": "did:..."} — no @context, no type — verified to nil and was returned
// as a presentation, and a VC 1.1 document could be signed under a 2.0 label.
// The credential side has had requireJOSECredential all along; this is its
// counterpart.
func requireJOSEPresentation(m PresentationData) error {
	if first := vcdm.FirstContext(m["@context"]); first != vcdm.ContextV2 {
		return fmt.Errorf("%s payload must name %q first in @context, got %q",
			TypeVPJWT, vcdm.ContextV2, first)
	}
	if !vcdm.HasType(m["type"], typeVerifiablePresentation) {
		return fmt.Errorf("%s payload must have type %s", TypeVPJWT, typeVerifiablePresentation)
	}

	return nil
}

// requireEnvelopedCredentials holds the credentials inside a vp+jwt to
// vc-jose-cose § 3.1.2: "Verifiable Credentials secured in verifiable
// presentations MUST use the Enveloped Verifiable Credential type".
//
// NewJOSEPresentation already envelopes what it carries and refuses a Data
// Integrity credential outright, but nothing checked the other direction: a bare
// vc+jwt string, or a bare JSON-LD credential object, verified to nil inside a
// vp+jwt. Both lose the data: URL that tells an outside verifier which mechanism
// secured the token, leaving it to guess.
//
// This cannot live in verifyCredentials, which the VP-JWT 1.1 and JSON-LD paths
// share: those carry their credentials bare, and legitimately so.
func requireEnvelopedCredentials(m PresentationData) error {
	// VCDM 2.0 lets verifiableCredential be a single value, not only an array.
	// Reading it as []interface{} and returning nil on a failed assertion folded
	// "no credentials" together with "one credential, unwrapped", so the same bare
	// credential was refused inside brackets and accepted without them.
	var items []interface{}
	switch v := m["verifiableCredential"].(type) {
	case nil:
		return nil // No credentials to hold to anything.
	case []interface{}:
		items = v
	default:
		items = []interface{}{v}
	}

	for i, item := range items {
		entry, ok := item.(map[string]interface{})
		if !ok || !vcdm.HasType(entry["type"], vc.TypeEnvelopedVC) {
			return fmt.Errorf(
				"credential at index %d must be an %s; a %s carries credentials enveloped, not bare",
				i, vc.TypeEnvelopedVC, TypeVPJWT)
		}
	}

	return nil
}

// envelopeMediaType names the scheme that secured a token, for the data: URL an
// EnvelopedVerifiableCredential carries. Only JWS is secured here, so the answer
// is fixed — but an unsigned token is refused now rather than enveloped under a
// label it has not earned. An SD-JWT would need its own media type, and
// ParseJOSECredential will not produce one.
func envelopeMediaType(token string) (string, error) {
	if parts := strings.Split(token, "."); len(parts) != 3 || parts[2] == "" {
		return "", fmt.Errorf("credential is not signed; sign it before putting it in a presentation")
	}
	return vc.TypeVCJWT, nil
}

// Deprecated: prefer AddProofByProvider with a signer provider; this legacy signing helper may be removed in a future release.
func (j *JOSEPresentation) AddProof(priv string, opts ...PresentationOpt) error {
	defaultSigner, err := signer.NewDefaultProvider(priv)
	if err != nil {
		return fmt.Errorf("failed to create default signer: %w", err)
	}
	return j.AddProofByProvider(defaultSigner, opts...)
}

func (j *JOSEPresentation) AddProofByProvider(signerProvider signer.SignerProvider, opts ...PresentationOpt) error {
	if signerProvider == nil {
		return fmt.Errorf("signer provider cannot be nil")
	}

	options := getOptions(opts...)
	if err := rejectBuildTimeOptions(options, false); err != nil {
		return err
	}
	payload, signingInput, err := j.pendingChallengeDomain(options)
	if err != nil {
		return err
	}

	digest := sha256.Sum256([]byte(signingInput))
	raw, err := signerProvider.Sign(digest[:])
	if err != nil {
		return fmt.Errorf("failed to sign signing input: %w", err)
	}
	// Accept trims a trailing recovery id, checks the 64-byte r||s shape, and
	// verifies the signature against the key the header names, so a signer that
	// does not hold that key fails here instead of at the verifier.
	signature, err := j.signingKey.Accept(signingInput, raw)
	if err != nil {
		return err
	}

	// Commit only once there is a signature to commit, and undo it if the
	// options reject what was produced, so a failed call leaves the
	// presentation exactly as it found it. Challenge and domain rewrite the
	// payload, so three fields move together and a rollback is unavoidable here.
	prevPayload, prevInput, prevSignature := j.payloadData, j.signingInput, j.signature
	j.payloadData, j.signingInput, j.signature = payload, signingInput, signature
	if err := j.executeOptions(signingOptions(opts)...); err != nil {
		j.payloadData, j.signingInput, j.signature = prevPayload, prevInput, prevSignature
		return err
	}

	return nil
}

// AddCustomProof attaches a signature produced outside the SDK over
// GetSigningInput, for a key the process never holds — an HSM, a wallet. Without
// it a vp+jwt presentation could only be signed by handing the key to the SDK,
// which locked those callers out of the format entirely.
//
// Challenge and domain cannot be applied here: the signature already covers the
// signing input, so rewriting the payload would invalidate it. Pass them to
// NewJOSEPresentation before GetSigningInput.
func (j *JOSEPresentation) AddCustomProof(proof *dto.Proof, opts ...PresentationOpt) error {
	if proof == nil {
		return fmt.Errorf("proof cannot be nil")
	}
	if len(proof.Signature) == 0 {
		return fmt.Errorf("proof signature cannot be empty")
	}
	if err := rejectBuildTimeOptions(getOptions(opts...), true); err != nil {
		return err
	}
	if err := j.executeOptions(signingOptions(opts)...); err != nil {
		return err
	}

	signature, err := j.signingKey.Accept(j.signingInput, proof.Signature)
	if err != nil {
		return err
	}
	j.signature = signature

	return nil
}

// GetSigningInput returns the bytes a signature must cover: base64url(header) +
// "." + base64url(payload). Pair it with AddCustomProof to sign outside the SDK,
// where the key cannot leave an HSM or a wallet. Not deprecated — this is the
// only path for a key the process never holds.
func (j *JOSEPresentation) GetSigningInput() ([]byte, error) {
	return []byte(j.signingInput), nil
}

func (j *JOSEPresentation) Verify(opts ...PresentationOpt) error {
	opts = append(opts, WithVerifyProof())
	return j.executeOptions(opts...)
}

func (j *JOSEPresentation) Serialize() (any, error) {
	if j.signature == "" {
		return j.signingInput, nil
	}
	return j.signingInput + "." + j.signature, nil
}

func (j *JOSEPresentation) Hash() (string, error) {
	if j.signature == "" {
		return "", fmt.Errorf("presentation must be signed before hashing")
	}

	serialized, err := j.Serialize()
	if err != nil {
		return "", fmt.Errorf("failed to serialize presentation: %w", err)
	}

	jwtStr, ok := serialized.(string)
	if !ok {
		return "", fmt.Errorf("unexpected serialized presentation type %T", serialized)
	}

	hash := sha256.Sum256([]byte(jwtStr))
	return hex.EncodeToString(hash[:]), nil
}

func (j *JOSEPresentation) GetContents() ([]byte, error) {
	return (*jsonmap.JSONMap)(&j.payloadData).ToJSON()
}

func (j *JOSEPresentation) GetType() string {
	return TypeJOSE
}

func (j *JOSEPresentation) ExtractField(path string) any {
	if j.payloadData == nil {
		return nil
	}
	return extractFieldFromMap(j.payloadData, path)
}

func (j *JOSEPresentation) executeOptions(opts ...PresentationOpt) error {
	options := getOptions(opts...)

	g := &errgroup.Group{}

	if options.isValidateVC {
		g.Go(func() error {
			if err := verifyCredentials(j.payloadData, options); err != nil {
				return fmt.Errorf("verify credentials: %w", err)
			}
			return nil
		})
	}

	if options.isVerifyProof {
		g.Go(func() error {
			// Built from the fields rather than through Serialize, which returns
			// any and so needs a type assertion back — and which returns the
			// unsigned two-segment input when there is no signature, leaving
			// VerifyJWT to report "invalid JWT format" about a presentation whose
			// only problem is that nobody signed it.
			if j.signature == "" {
				return fmt.Errorf("presentation is not signed")
			}

			verifier := jwt.NewJWTVerifier(options.resolver)
			if err := verifier.VerifyJWT(j.signingInput + "." + j.signature); err != nil {
				return fmt.Errorf("verify proof: %w", err)
			}
			// exp and nbf bound the signature, not the presentation, so they
			// belong to this check and not to the optional expiry check on
			// validFrom/validUntil.
			if err := jwtutil.CheckTimeClaims(j.payloadData, time.Now()); err != nil {
				return fmt.Errorf("verify proof: %w", err)
			}
			if err := j.checkChallengeAndDomain(options); err != nil {
				return fmt.Errorf("verify proof: %w", err)
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return fmt.Errorf("presentation verification failed: %w", err)
	}

	if options.isCheckExpiration {
		if err := checkExpiration(j.payloadData); err != nil {
			return fmt.Errorf("failed to check expiration: %w", err)
		}
	}

	return nil
}

// pendingChallengeDomain returns the payload and signing input that this call's
// challenge and domain would produce, WITHOUT writing them into j.
//
// Both go into the signed bytes, so they have to be applied before signing — but
// applying them to j directly meant a signing failure left them behind, and the
// next call, asking for neither, signed the previous attempt's nonce and aud
// into a presentation addressed to a verifier the caller never named. The
// caller commits the result only once signing has succeeded.
func (j *JOSEPresentation) pendingChallengeDomain(options *presentationOptions) (PresentationData, string, error) {
	if options.challenge == "" && options.domain == "" {
		return j.payloadData, j.signingInput, nil
	}
	if j.payloadData == nil {
		return nil, "", fmt.Errorf("presentation has no payload data to update")
	}

	payload := make(PresentationData, len(j.payloadData)+2)
	for k, v := range j.payloadData {
		payload[k] = v
	}
	if options.challenge != "" {
		payload["nonce"] = options.challenge
	}
	if options.domain != "" {
		payload["aud"] = options.domain
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, "", fmt.Errorf("failed to marshal payload: %w", err)
	}
	header, _, _ := strings.Cut(j.signingInput, ".")
	return payload, header + "." + base64.RawURLEncoding.EncodeToString(payloadJSON), nil
}

func (j *JOSEPresentation) checkChallengeAndDomain(options *presentationOptions) error {
	if options.expectedChallenge != "" {
		nonce, _ := j.payloadData["nonce"].(string)
		if nonce != options.expectedChallenge {
			return fmt.Errorf("nonce %q does not match expected challenge %q", nonce, options.expectedChallenge)
		}
	}
	return checkAudience(j.payloadData["aud"], options)
}
