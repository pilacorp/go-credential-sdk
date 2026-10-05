package vc

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
	"github.com/pilacorp/go-credential-sdk/credential/common/sdjwt"
	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	"github.com/pilacorp/go-credential-sdk/credential/internal/jwtutil"
	"golang.org/x/sync/errgroup"
)

// JOSECredential implements W3C VC 2.0 Securing Verifiable Credentials using JOSE (vc-jose-cose).
// In vc-jose-cose, the unsecured Verifiable Credential is the unencoded JWS payload (flat,
// without the legacy "vc" wrapper claim), and the header carries typ: "vc+jwt".
type JOSECredential struct {
	signingInput string         // JWS header.payload (base64 encoded)
	payloadData  CredentialData // Unsecured VC as CredentialData
	signature    string         // JWS signature (if signed)
	disclosures  []string       // SD-JWT disclosures, when the credential is secured that way
	disclosable  bool           // Payload carries _sd digests, even if this holder reveals none
	signingKey   jwt.SigningKey // Verification method the header names; zero for a parsed credential
}

var _ Credential = (*JOSECredential)(nil)

// NewJOSECredential creates a new Verifiable Credential secured with JOSE per W3C vc-jose-cose.
func NewJOSECredential(vcc CredentialContents, opts ...CredentialOpt) (*JOSECredential, error) {
	// The vc+jwt media type names version 2, so the document has to be one.
	// Defaulting an empty context is a convenience; quietly signing a v1
	// document under a v2 label is not, so that case is refused instead.
	if len(vcc.Context) == 0 {
		vcc.Context = []interface{}{credentialsV2Context}
	} else if err := requireV2Context(vcc.Context); err != nil {
		return nil, err
	}

	m, err := serializeCredentialContents(&vcc)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize credential contents: %w", err)
	}

	vcMap := normalizeCredentialData(m)
	options := getOptions(opts...)
	if err := rejectPrebuiltDisclosures(options); err != nil {
		return nil, err
	}

	// The same check ParseJOSECredential runs, so the two ends cannot disagree
	// about what a vc+jwt is. serializeCredentialContents already refuses a
	// missing type, issuer or credentialSubject, which left one gap: a type that
	// exists but does not name VerifiableCredential — ["AlumniCredential"] alone,
	// or ["VerifiablePresentation"] — signed here and then refused by the
	// verifier. Running the whole function rather than only the part that gap
	// needs is the point: one function, both ends.
	if err := requireJOSECredential(CredentialData(vcMap)); err != nil {
		return nil, err
	}

	// Selective disclosure replaces the named fields with digests and returns the
	// values separately, for the holder to send or withhold. Only fields inside
	// credentialSubject may be hidden: everything at the top level is metadata a
	// verifier decides on, and ParseJOSECredential refuses a payload whose root
	// carries _sd for exactly that reason.
	result, err := sdjwt.BuildDisclosures(sdjwt.BuildDisclosuresInput{
		VC:             vcMap,
		SelectivePaths: options.sdSelectivePaths,
		HashAlgorithm:  options.sdAlg,
		Shuffle:        options.sdShuffle,
		Decoys:         options.sdDecoys,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to build SD-JWT disclosures: %w", err)
	}
	vcMap = result.ProcessedVC
	disclosures := result.Disclosures

	// Same rule the parse side applies: a top-level property must not be
	// disclosable. Reachable here through WithSDDecoyDigests with a root path.
	if err := requireDisclosableAtTopLevel(vcMap); err != nil {
		return nil, err
	}

	// Read from the payload, which is the same question ParseJOSECredential asks
	// of the same bytes. Deriving it from len(disclosures) instead made the two
	// ends disagree about decoys-only credentials — BuildDisclosures writes
	// _sd_alg and the decoy digests but returns no disclosure, so the issuer
	// labelled the token vc+jwt and left the "~" off while the parser, reading
	// _sd_alg, folded the digests out and put the "~" back. Same credential, two
	// byte forms, two Hash values.
	_, disclosable := vcMap["_sd_alg"]

	// Per W3C vc-jose-cose Section 1.1.2.1:
	// "The JWT Claim Names vc and vp MUST NOT be present in any JWT Claims Set that
	// comprises a verifiable credential or a verifiable presentation."
	delete(vcMap, "vc")
	delete(vcMap, "vp")

	// Without iat the verifier has no signing time to compare a soft revocation
	// against, and would have to guess one from validFrom — a different fact.
	jwtutil.SetIssuedAt(vcMap, time.Now())

	payloadData := CredentialData(vcMap)

	// Resolve the verification method the header will name, and keep it: every
	// signing path checks the signature it is handed against this key before
	// attaching it, so a signature made by another key fails here rather than at
	// whoever receives the credential.
	signingKey, err := jwt.ResolveSigningKey(context.Background(), vcc.Issuer,
		"assertionMethod", options.verificationMethodKey, options.resolver)
	if err != nil {
		return nil, err
	}

	// typ names the securing mechanism, so it follows the payload rather than
	// being fixed: vc-jose-cose § 3.2.1 says vc+jwt when securing with JWS and
	// vc+sd-jwt when securing with SD-JWT. A verifier routes on this, and one
	// told vc+jwt parses the token as plain JWS and chokes on the disclosures
	// trailing the signature.
	//
	// Decoy digests count. They carry no disclosure, but a verifier still has to
	// run SD-JWT processing to fold them out, and one that does not sees _sd and
	// _sd_alg sitting in credentialSubject as though they were claims.
	//
	// jwt.purposeFromTyp has to recognise whichever value lands here — a typ the
	// parser routes but the purpose check does not know is decided by the
	// payload, which the signer writes.
	header := map[string]interface{}{
		"typ": TypeVCJWT,
		"alg": signingKey.Alg,
		"kid": signingKey.ID,
	}
	if disclosable {
		header["typ"] = TypeVCSDJWT
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal header: %w", err)
	}
	headerEncoded := base64.RawURLEncoding.EncodeToString(headerJSON)

	payloadJSON, err := json.Marshal(vcMap)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}
	payloadEncoded := base64.RawURLEncoding.EncodeToString(payloadJSON)

	signingInput := headerEncoded + "." + payloadEncoded

	e := &JOSECredential{
		signingInput: signingInput,
		payloadData:  payloadData,
		signature:    "",
		disclosures:  disclosures,
		disclosable:  disclosable,
		signingKey:   signingKey,
	}

	return e, e.executeOptions(opts...)
}

// ParseJOSECredential parses a W3C vc-jose-cose (vc+jwt) token.
func ParseJOSECredential(rawJWT string, opts ...CredentialOpt) (*JOSECredential, error) {
	rawJWT = strings.TrimSpace(strings.Trim(rawJWT, "\""))

	// A tilde means disclosures follow the signature. The issuer-signed JWT is
	// what the signature covers; the disclosures travel beside it and are folded
	// back into the payload below.
	var issuerJWT string
	var disclosures []string
	if sdjwt.IsSDJWT(rawJWT) {
		parsed, perr := sdjwt.Parse(rawJWT)
		if perr != nil {
			return nil, fmt.Errorf("failed to parse SD-JWT: %w", perr)
		}
		issuerJWT = parsed.BaseJWT
		disclosures = parsed.Disclosures
	} else {
		if !isJWTCredential(rawJWT) {
			return nil, fmt.Errorf("invalid JWT or SD-JWT format")
		}
		issuerJWT = rawJWT
	}

	parts := strings.Split(issuerJWT, ".")
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
	if !isJOSECredentialTyp(typ) {
		return nil, fmt.Errorf("invalid typ header for JOSECredential: got %q, want %q or %q",
			typ, TypeVCJWT, TypeVCSDJWT)
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

	// Whatever the holder chose to send, the issuer must not have made a
	// top-level property disclosable in the first place: a withheld disclosure
	// leaves only a digest, which does not say which property it stood for, so
	// there would be nothing left to check.
	if err := requireDisclosableAtTopLevel(payloadMap); err != nil {
		return nil, err
	}

	vcMap := payloadMap
	// Gated on the payload, not on how many disclosures arrived. Reconstruct is
	// also what strips the _sd arrays and _sd_alg, so a holder revealing nothing
	// used to hand the caller a credentialSubject with a raw digest array sitting
	// in it as though it were a claim — and schema validation then saw a property
	// the schema does not know. _sd_alg is the marker: BuildDisclosures writes it
	// at the root for every SD-JWT, whatever the paths were.
	_, disclosable := payloadMap["_sd_alg"]
	if disclosable || len(disclosures) > 0 {
		processed, rerr := sdjwt.Reconstruct(vcMap, disclosures, true)
		if rerr != nil {
			return nil, fmt.Errorf("failed to reconstruct SD-JWT payload: %w", rerr)
		}
		vcMap = processed
	}

	// Reconstruct deep-copies, so payloadMap is still exactly what the signature
	// covered while vcMap is what the caller will read. A disclosure that arrived
	// carrying one of the claims a verifier decides on is named here; one that was
	// withheld was already refused above.
	if err := requireSecuredClaimsSigned(payloadMap, vcMap); err != nil {
		return nil, fmt.Errorf("invalid %s payload: %w", typ, err)
	}

	// A signature proves who produced these bytes, not that the bytes are a
	// credential. The typ header already promised one, so hold the payload to
	// that promise here — otherwise a v1 document, a presentation, or a payload
	// with no @context at all verifies to nil and is handed back as a VC.
	if err := requireJOSECredential(CredentialData(vcMap)); err != nil {
		return nil, err
	}

	signingInput := headerEncoded + "." + payloadEncoded

	e := &JOSECredential{
		signingInput: signingInput,
		payloadData:  CredentialData(vcMap),
		signature:    signature,
		disclosures:  disclosures,
		disclosable:  disclosable,
	}

	return e, e.executeOptions(opts...)
}

// The media types vc-jose-cose gives a secured credential, named by the typ
// header and by the data: URL of an EnvelopedVerifiableCredential. Which one
// applies depends on the securing mechanism: JWS gives vc+jwt, SD-JWT gives
// vc+sd-jwt.
const (
	TypeVCJWT       = "vc+jwt"
	TypeVCSDJWT     = "vc+sd-jwt"
	TypeEnvelopedVC = "EnvelopedVerifiableCredential"
)

// TypeJOSE is what GetType reports for a credential secured with vc-jose-cose.
// Consumers branch on this value, so it is exported rather than left as a
// literal they have to spell correctly on both sides of a version bump.
const TypeJOSE = "JOSE"

// isJOSECredentialTyp reports whether typ names a credential secured the way
// vc-jose-cose defines, in either the short or the full media type spelling.
//
// jwt.purposeFromTyp has to recognise every value accepted here, or a token this
// function routes would have its kind decided by its own payload. Adding one
// means adding it there.
func isJOSECredentialTyp(typ string) bool {
	switch typ {
	case TypeVCJWT, "application/" + TypeVCJWT, TypeVCSDJWT, "application/" + TypeVCSDJWT:
		return true
	}
	return false
}

// Deprecated: prefer AddProofByProvider with a signer provider; this legacy signing helper may be removed in a future release.
func (j *JOSECredential) AddProof(priv string, opts ...CredentialOpt) error {
	defaultSigner, err := signer.NewDefaultProvider(priv)
	if err != nil {
		return fmt.Errorf("failed to create default signer: %w", err)
	}
	return j.AddProofByProvider(defaultSigner, opts...)
}

func (j *JOSECredential) AddProofByProvider(signerProvider signer.SignerProvider, opts ...CredentialOpt) error {
	if signerProvider == nil {
		return fmt.Errorf("signer provider cannot be nil")
	}

	if err := rejectBuildTimeOptions(getOptions(opts...)); err != nil {
		return err
	}
	if err := j.executeOptions(signingOptions(opts)...); err != nil {
		return err
	}

	digest := sha256.Sum256([]byte(j.signingInput))
	raw, err := signerProvider.Sign(digest[:])
	if err != nil {
		return fmt.Errorf("failed to sign signing input: %w", err)
	}
	// Accept trims a trailing recovery id, checks the 64-byte r||s shape, and
	// verifies the signature against the key the header names. Assigned only
	// after all of that, so a failed call needs no rollback and cannot clear a
	// signature the credential already had.
	signature, err := j.signingKey.Accept(j.signingInput, raw)
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
func (j *JOSECredential) GetSigningInput() ([]byte, error) {
	return []byte(j.signingInput), nil
}

// AddCustomProof attaches a signature produced outside the SDK over
// GetSigningInput. Not deprecated, for the same reason: an HSM signs, the SDK
// attaches.
func (j *JOSECredential) AddCustomProof(proof *dto.Proof, opts ...CredentialOpt) error {
	if proof == nil {
		return fmt.Errorf("proof cannot be nil")
	}
	if len(proof.Signature) == 0 {
		return fmt.Errorf("proof signature cannot be empty")
	}

	if err := rejectBuildTimeOptions(getOptions(opts...)); err != nil {
		return err
	}
	if err := j.executeOptions(signingOptions(opts)...); err != nil {
		return err
	}

	// The same check AddProofByProvider runs. A signature produced outside the
	// SDK — an HSM, a wallet — is still a signature by some key over some data,
	// and this is where it is held to being the right key over this input.
	signature, err := j.signingKey.Accept(j.signingInput, proof.Signature)
	if err != nil {
		return err
	}
	j.signature = signature

	return nil
}

func (j *JOSECredential) Verify(opts ...CredentialOpt) error {
	opts = append(opts, WithVerifyProof())
	return j.executeOptions(opts...)
}

// Serialize returns the token to hand to someone else: the issuer-signed JWT,
// and for an SD-JWT the disclosures this holder is willing to reveal, each after
// a "~". Verification does not go through here — it rebuilds the issuer JWT from
// signingInput and signature, because the disclosures are outside the signature
// and feeding them to a JWS verifier fails as a base64 error (issue #78).
func (j *JOSECredential) Serialize() (any, error) {
	base := j.signingInput
	if j.signature != "" {
		base += "." + j.signature
	}
	if !j.disclosable {
		return base, nil
	}

	// Terminated even with no disclosure left to write: the payload still holds
	// the digests, so dropping the "~" would hand out a token whose typ header
	// says vc+sd-jwt while its shape says plain JWS — and envelopeMediaType, which
	// reads the token, then labelled the envelope in a presentation vc+jwt.
	var sb strings.Builder
	sb.WriteString(base)
	for _, d := range j.disclosures {
		if d == "" {
			continue
		}
		sb.WriteString("~")
		sb.WriteString(d)
	}
	sb.WriteString("~")

	return sb.String(), nil
}

// DecodedDisclosures reports which fields this token still discloses, decoded
// from the salted arrays that travel after the signature.
func (j *JOSECredential) DecodedDisclosures() ([]sdjwt.DecodedDisclosure, error) {
	return sdjwt.DecodeDisclosures(j.disclosures)
}

// Present returns the same credential carrying only selectedDisclosures, which
// is how a holder reveals a subset. The issuer-signed JWT is untouched, so the
// signature still verifies; what changes is how much of the payload can be
// reconstructed from it.
func (j *JOSECredential) Present(selectedDisclosures []string) (Credential, error) {
	if j.signature == "" {
		return nil, fmt.Errorf("cannot present an unsigned credential")
	}
	issuerJWT := j.signingInput + "." + j.signature

	// Nothing was made disclosable, so there is no subset to choose and the
	// token is already everything the holder has. Said plainly rather than
	// returning the same credential under an SD-JWT terminator it has not
	// earned — the typ header would still say vc+jwt.
	if len(j.disclosures) == 0 {
		return nil, fmt.Errorf("credential carries no disclosures; nothing to present selectively")
	}

	return ParseJOSECredential(sdjwt.BuildSDJWTPresentation(issuerJWT, selectedDisclosures))
}

func (j *JOSECredential) Hash() (string, error) {
	if j.signature == "" {
		return "", fmt.Errorf("credential must be signed before hashing")
	}

	serialized, err := j.Serialize()
	if err != nil {
		return "", fmt.Errorf("failed to serialize credential: %w", err)
	}

	jwtStr, ok := serialized.(string)
	if !ok {
		return "", fmt.Errorf("unexpected serialized credential type %T", serialized)
	}

	hash := sha256.Sum256([]byte(jwtStr))
	return hex.EncodeToString(hash[:]), nil
}

func (j *JOSECredential) GetContents() ([]byte, error) {
	return (*jsonmap.JSONMap)(&j.payloadData).ToJSON()
}

func (j *JOSECredential) GetType() string {
	return TypeJOSE
}

func (j *JOSECredential) ExtractField(path string) any {
	if j.payloadData == nil {
		return nil
	}
	return extractFieldFromMap(j.payloadData, path)
}

func (j *JOSECredential) executeOptions(opts ...CredentialOpt) error {
	options := getOptions(opts...)

	g := &errgroup.Group{}

	if options.isValidateSchema {
		g.Go(func() error {
			if err := validateCredential(j.payloadData, options); err != nil {
				return fmt.Errorf("validate credential: %w", err)
			}
			return nil
		})
	}

	if options.isCheckRevocation {
		g.Go(func() error {
			if err := checkRevocation(j.payloadData); err != nil {
				return fmt.Errorf("check revocation: %w", err)
			}
			return nil
		})
	}

	if options.isVerifyProof {
		g.Go(func() error {
			if j.signature == "" {
				return fmt.Errorf("credential is not signed")
			}
			// Verify cryptographic signature of the Base JWS token directly,
			// ignoring any SD-JWT disclosures or presentation envelopes.
			baseJWS := j.signingInput + "." + j.signature
			verifier := jwt.NewJWTVerifier(options.resolver)
			if err := verifier.VerifyJWT(baseJWS); err != nil {
				return fmt.Errorf("verify proof: %w", err)
			}
			// exp and nbf bound the signature, not the credential, so they
			// belong to this check and not to the optional expiry check on
			// validFrom/validUntil.
			if err := jwtutil.CheckTimeClaims(j.payloadData, time.Now()); err != nil {
				return fmt.Errorf("verify proof: %w", err)
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return fmt.Errorf("credential verification failed: %w", err)
	}

	if options.isCheckExpiration {
		if err := checkExpiration(j.payloadData); err != nil {
			return fmt.Errorf("failed to check expiration: %w", err)
		}
	}

	return nil
}
