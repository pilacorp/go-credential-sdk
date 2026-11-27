package vc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/pilacorp/go-credential-sdk/credential/common/dto"
	"github.com/pilacorp/go-credential-sdk/credential/common/jsonmap"
	"github.com/pilacorp/go-credential-sdk/credential/common/jwt"
	"github.com/pilacorp/go-credential-sdk/credential/common/sdjwt"
	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	"github.com/pilacorp/go-credential-sdk/credential/internal/jwtutil"
	"github.com/pilacorp/go-credential-sdk/jose"
	"github.com/pilacorp/go-credential-sdk/jose/jws"
	josesdjwt "github.com/pilacorp/go-credential-sdk/jose/sdjwt"
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
		Decoys:         options.sdDecoys,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to build SD-JWT disclosures: %w", err)
	}
	vcMap = result.ProcessedVC

	// WithSDDisclosures carries disclosures the caller built itself, against
	// digests the caller put in the document — the advanced path the README
	// documents. Refusing it outright was wrong: the reason given, that a
	// disclosure made elsewhere cannot match a digest this payload holds, is
	// true only when the builder generated the digests from
	// WithSDSelectivePaths. When the caller supplied both halves they do match,
	// and a credential that signed and verified before stopped building at all.
	//
	// So the question asked here is the one that actually matters — do these
	// disclosures match the digests in this payload — and Reconstruct answers it
	// by doing the work. It brings the § 7.1 rules with it: a disclosure that
	// matches nothing, the same one twice, a digest referenced twice.
	disclosures := make([]string, 0, len(result.Disclosures)+len(options.sdDisclosures))
	disclosures = append(disclosures, result.Disclosures...)
	disclosures = append(disclosures, options.sdDisclosures...)

	// _sd_alg has to be written for prebuilt disclosures too, because it is what
	// marks the payload as selectively disclosed further down. BuildDisclosures
	// only writes it for paths and decoys it generated itself, so a prebuilt-only
	// credential had none — and then the typ stayed vc+jwt, Serialize dropped the
	// disclosures and the terminator, and the digests the caller put in the
	// subject leaked back out on the next parse. Defaulted rather than demanded:
	// RFC 9901 § 4.1.1 makes the claim optional and sha-256 the default.
	if len(options.sdDisclosures) > 0 {
		if _, ok := vcMap["_sd_alg"]; !ok {
			alg := options.sdAlg
			if alg == "" {
				alg = sdjwt.DefaultHashAlgorithm
			}
			vcMap["_sd_alg"] = alg
		}
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

	// The parser's rules (the SDK's own: nothing disclosable outside
	// credentialSubject; RFC 9901 §7.1: the disclosures matching the digests)
	// run on the bytes that will be signed, whatever Go types the caller's
	// contents held. A first run with a provisional header refuses a bad
	// configuration before the DID is resolved, which may cost a network call.
	if _, err := assembleJOSECredential(vcMap, payloadData, disclosures, disclosable,
		jwt.SigningKey{ID: options.verificationMethodKey, Alg: jwt.AlgES256}, true); err != nil {
		return nil, err
	}

	// Resolve the verification method the header will name, and keep it: every
	// signing path checks the signature it is handed against this key before
	// attaching it, so a signature made by another key fails here rather than at
	// whoever receives the credential.
	signingKey, err := jwt.ResolveSigningKey(context.Background(), vcc.Issuer,
		"assertionMethod", options.verificationMethodKey, options.resolver)
	if err != nil {
		return nil, err
	}

	// Again with the real header. Only alg and kid changed, and no parse
	// rule reads them, so the header bound is checked again and, for an
	// SD-JWT, the size jose/sdjwt.Split caps, which the kid's length moves.
	e, err := assembleJOSECredential(vcMap, payloadData, disclosures, disclosable, signingKey, false)
	if err != nil {
		return nil, err
	}
	if disclosable {
		if err := e.checkSplittable(); err != nil {
			return nil, err
		}
	}
	return e, e.executeOptions(opts...)
}

// assembleJOSECredential writes the header for key and the payload, and
// refuses a credential ParseJOSECredential would refuse once signed.
//
// typ names the securing mechanism, so it follows the payload rather than
// being fixed: vc-jose-cose (W3C REC 2026-10-13) §3.1.1 says typ SHOULD be
// vc+jwt when securing with JOSE, and §3.2.1 that it SHOULD be vc+sd-jwt when
// securing with SD-JWT. A verifier routes on this, and one
// told vc+jwt parses the token as plain JWS and chokes on the disclosures
// trailing the signature. Decoy digests count: they carry no disclosure, but
// a verifier still has to run SD-JWT processing to fold them out.
// jwt.purposeFromTyp has to recognise whichever value lands here.
func assembleJOSECredential(vcMap map[string]interface{}, payloadData CredentialData, disclosures []string, disclosable bool, key jwt.SigningKey, parseBack bool) (*JOSECredential, error) {
	header := map[string]interface{}{
		"typ": TypeVCJWT,
		"alg": key.Alg,
		"kid": key.ID,
	}
	if disclosable {
		header["typ"] = TypeVCSDJWT
	}
	headerEncoded, err := jwtutil.MarshalSegment(header)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal header: %w", err)
	}
	if err := jwtutil.CheckHeaderToSign(headerEncoded, key.ID); err != nil {
		return nil, err
	}
	payloadEncoded, err := jwtutil.MarshalSegment(vcMap)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}
	e := &JOSECredential{
		signingInput: headerEncoded + "." + payloadEncoded,
		payloadData:  payloadData,
		disclosures:  disclosures,
		disclosable:  disclosable,
		signingKey:   key,
	}
	if !parseBack {
		return e, nil
	}
	if err := e.checkParsable(); err != nil {
		return nil, err
	}
	return e, nil
}

// ParseJOSECredential parses a W3C vc-jose-cose (vc+jwt) token.
func ParseJOSECredential(rawJWT string, opts ...CredentialOpt) (*JOSECredential, error) {
	rawJWT = strings.TrimSpace(strings.Trim(rawJWT, "\""))

	// A tilde means disclosures follow the signature. jose/sdjwt.Split
	// handles the combined form (RFC 9901 section 4), including the case where a
	// Key Binding JWT trails the disclosures. It rejects duplicates,
	// empty disclosures and a missing trailing ~.
	var issuerJWT string
	var disclosures []string
	// combinedSD: the token is in the combined form, which Split accepted.
	combinedSD := strings.Contains(rawJWT, "~")
	if combinedSD {
		ij, ds, kbJWT, serr := josesdjwt.Split(rawJWT)
		if serr != nil {
			return nil, fmt.Errorf("failed to parse SD-JWT: %w", serr)
		}
		// RFC 9901 section 7.2: a Holder that receives an SD-JWT+KB MUST
		// reject it; section 4: a Verifier that expects an SD-JWT MUST check
		// that the final component is empty. The SDK verifies no Key Binding
		// JWT yet, so it expects an SD-JWT on both paths.
		if kbJWT != "" {
			return nil, fmt.Errorf("failed to parse SD-JWT: SD-JWT carries a key binding JWT, which this SDK does not verify yet; present the credential without it")
		}
		issuerJWT = ij
		disclosures = ds
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

	// Read by module jose's rules: over 64 KiB, a duplicate key, invalid
	// UTF-8 or trailing data is refused, as jose/jws.Verify refuses it.
	headerMap, err := jwtutil.DecodeHeaderSegment(headerEncoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode header: %w", err)
	}
	typ, _ := headerMap["typ"].(string)
	if !isJOSECredentialTyp(typ) {
		return nil, fmt.Errorf("invalid typ header for JOSECredential: got %.64q, want %q or %q",
			typ, TypeVCJWT, TypeVCSDJWT)
	}
	// RFC 9901 §4: the last tilde of an SD-JWT MUST NOT be omitted, and a
	// Verifier that expects one MUST check it. common/sdjwt.Parse refuses it
	// too: IsSDJWT needs a "~".
	if !combinedSD && (jws.Header{"typ": typ}).TypIs(TypeVCSDJWT) {
		return nil, fmt.Errorf("failed to parse SD-JWT: %w: a %s token ends in \"~\" (RFC 9901 §4)", jose.ErrMalformed, TypeVCSDJWT)
	}

	payloadBytes, err := jose.DecodeSegment(payloadEncoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}

	payloadMap, err := jwtutil.DecodeJSONObject(payloadBytes)
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

	// Whether this token is an SD-JWT is answered by the two things that say how
	// it was secured — the media type in the header, and the combined format —
	// not by a claim inside the payload. _sd_alg looked like the marker because
	// BuildDisclosures always writes it, but RFC 9901 § 4.1.1 makes it OPTIONAL
	// and defaults it to sha-256, so an SD-JWT from another implementation need
	// not carry it. Reading it as the marker left such a token with
	// disclosable=false: Reconstruct never ran, so the _sd digests stayed in the
	// document as though they were claims, Serialize dropped the disclosures and
	// the terminator, and the claim the holder did send was gone after a round
	// trip. It is kept below only as a third signal, never as the only one.
	_, hasSDAlg := payloadMap["_sd_alg"]
	declaredSD := jws.Header{"typ": typ}.TypIs(TypeVCSDJWT)

	// The header must not disagree with the bytes. A token typed vc+jwt means
	// plain JWS to every other verifier, which parses it that way and chokes on
	// the disclosures after the signature; this one used to accept it and
	// reconstruct, so the two ends read the same token differently.
	//
	// A vc+jwt whose payload carries _sd with neither a terminator nor _sd_alg
	// gives neither signal, so it slips past this one; the walk below catches it,
	// which is why that walk is told whether the media type declared SD.
	if !declaredSD && (combinedSD || hasSDAlg) {
		return nil, fmt.Errorf("typ %.64q does not match the SD-JWT format", typ)
	}

	// Whatever the holder chose to send, the issuer must not have made anything
	// outside credentialSubject disclosable in the first place: a withheld
	// disclosure leaves only a digest, which does not say which property it
	// stood for, so there would be nothing left to check. Runs before
	// Reconstruct, because Reconstruct is what removes the evidence.
	if err := requireDisclosableAtTopLevel(payloadMap, declaredSD); err != nil {
		return nil, err
	}

	vcMap := payloadMap
	// common/sdjwt.Reconstruct (jose/sdjwt.RecreateWithOptions) is also what
	// strips the _sd arrays and _sd_alg, so it has to run whenever the token
	// is an SD-JWT — not only when a
	// disclosure arrived. A holder revealing nothing used to hand the caller a
	// credentialSubject with a raw digest array sitting in it as though it
	// were a claim, and schema validation then saw a property the schema does
	// not know.
	//
	// It applies RFC 9901 §7.1: undisclosed array elements are removed (step
	// 3d), disclosure names "_sd" and "..." are rejected (step 3c.ii.2), and
	// duplicate digests are refused (step 4). jose also refuses a disclosure
	// named "_sd_alg", which §4.1.1 keeps at the top level.
	// Disclosures imply the combined form, so these three signals cover it.
	disclosable := declaredSD || combinedSD || hasSDAlg
	if disclosable {
		recreated, rerr := sdjwt.Reconstruct(payloadMap, disclosures, true)
		if rerr != nil {
			return nil, fmt.Errorf("failed to reconstruct SD-JWT payload: %w", rerr)
		}
		vcMap = recreated
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
// Case is ignored and "application/" is implied (RFC 7515 §4.1.9).
func isJOSECredentialTyp(typ string) bool {
	h := jws.Header{"typ": typ}
	return h.TypIs(TypeVCJWT) || h.TypIs(TypeVCSDJWT)
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

	o := getOptions(opts...)
	if err := rejectBuildTimeOptions(o); err != nil {
		return err
	}
	if err := refuseOverwrite(j.signature, o); err != nil {
		return err
	}
	if err := j.executeOptions(signingOptions(opts)...); err != nil {
		return err
	}

	// Sign checks the 64-byte r||s shape and verifies the signature against
	// the key the header names, so a signer that does not hold that key fails
	// here instead of at the verifier.
	signature, err := j.signingKey.Sign(j.signingInput, signerProvider)
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

	o := getOptions(opts...)
	if err := rejectBuildTimeOptions(o); err != nil {
		return err
	}
	if err := refuseOverwrite(j.signature, o); err != nil {
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
// is how a holder reveals a subset. A disclosure nested in a concealed claim
// needs that claim's disclosure selected too: RFC 9901 §7.2 has the Holder
// check that each selected disclosure's digest is in the Issuer-signed JWT
// or in another selected disclosure (presentation step 2); Present refuses the
// selection and names what to add, rather than revealing it unasked.
// The refusal is a *ParentDisclosureError, which matches
// ErrParentDisclosureNotSelected; its Missing field lists every disclosure
// the selection lacks, each chain innermost first, so presenting again with
// them added passes this check.
// The issuer-signed JWT is untouched, so the signature still verifies; what
// changes is how much of the payload can be reconstructed from it.
func (j *JOSECredential) Present(selectedDisclosures []string) (Credential, error) {
	if j.signature == "" {
		return nil, fmt.Errorf("cannot present an unsigned credential")
	}
	issuerJWT := j.signingInput + "." + j.signature

	// Nothing was made disclosable, so there is no subset to choose and the
	// token is already everything the holder has. Said plainly rather than
	// returning the same credential under an SD-JWT terminator it has not
	// earned — the typ header would still say vc+jwt.
	//
	// Read from disclosable, the same field Serialize and the typ header read.
	// len(j.disclosures) is a different question and gave a different answer:
	// a credential carrying only decoy digests, and one that came out of an
	// earlier Present(nil), are both SD-JWTs with no disclosure left to list,
	// and both were refused here while Serialize still terminated them with "~".
	if !j.disclosable {
		return nil, fmt.Errorf("credential carries no disclosures; nothing to present selectively")
	}

	payload, err := jwtutil.DecodeSegmentObject(strings.SplitN(j.signingInput, ".", 2)[1])
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}
	if err := requireParentsSelected(payload, j.disclosures, selectedDisclosures); err != nil {
		return nil, err
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

	if options.isCheckRevocation && !options.isVerifyProof {
		return fmt.Errorf("credential verification failed: WithCheckRevocation requires WithVerifyProof — the credential's proof must be verified before fetching its status list")
	}

	g := &errgroup.Group{}

	if options.isValidateSchema {
		g.Go(func() error {
			if err := validateCredential(j.payloadData, options); err != nil {
				return fmt.Errorf("validate credential: %w", err)
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
			// belong to this check and not to the optional expiry check on the
			// document's dates (vcdm.CheckValidity).
			if err := jwtutil.CheckTimeClaims(j.payloadData, options.leeway); err != nil {
				return fmt.Errorf("verify proof: %w", err)
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return fmt.Errorf("credential verification failed: %w", err)
	}

	// Revocation check runs after the proof is verified: an unsigned or
	// forged credential must not trigger a GET to the statusListCredential
	// URL the attacker chose.
	if options.isCheckRevocation {
		if err := checkRevocation(j.payloadData, options); err != nil {
			return fmt.Errorf("credential verification failed: check revocation: %w", err)
		}
	}

	if options.isCheckExpiration {
		if err := checkExpiration(j.payloadData, options.leeway); err != nil {
			return fmt.Errorf("failed to check expiration: %w", err)
		}
	}

	return nil
}

// checkParsable refuses, before anything is signed, a credential that
// ParseJOSECredential would refuse once signed: it parses the finished token
// with a placeholder signature. Accept takes only a 64-byte signature, so the
// placeholder of its encoded length gives the token its final size, and the
// parser's limits (1 MiB and 1000 disclosures for an SD-JWT, nesting depth)
// apply as they will.
func (j *JOSECredential) checkParsable() error {
	token, err := j.placeholderToken()
	if err != nil {
		return err
	}
	if _, err := ParseJOSECredential(token); err != nil {
		if j.disclosable || len(j.disclosures) > 0 {
			return fmt.Errorf("invalid SD-JWT disclosures: the SDK cannot parse back this credential: %w", err)
		}
		return fmt.Errorf("the SDK cannot parse back this credential: %w", err)
	}
	return nil
}

// checkSplittable refuses an SD-JWT that jose/sdjwt.Split, which every
// reader runs first, would refuse once signed: over 1 MiB or 1000 disclosures.
func (j *JOSECredential) checkSplittable() error {
	token, err := j.placeholderToken()
	if err != nil {
		return err
	}
	if _, _, _, err := josesdjwt.Split(token); err != nil {
		return fmt.Errorf("invalid SD-JWT disclosures: the SDK cannot parse back this credential: %w", err)
	}
	return nil
}

// placeholderToken is j serialized with a placeholder signature of the
// final length, the bytes a reader will get once j is signed.
func (j *JOSECredential) placeholderToken() (string, error) {
	signed := *j
	signed.signature = jwtutil.PlaceholderSignature()
	token, err := signed.Serialize()
	if err != nil {
		return "", err
	}
	return token.(string), nil
}

// requireParentsSelected refuses a selection holding a disclosure nested in
// a concealed claim whose own disclosure is not selected, naming every
// disclosure the selection lacks, so one refusal says all there is to add.
// Adding the parents would reveal their other members without the holder
// choosing to. payload is the Issuer-signed JWT payload and all the
// credential's disclosures; jose/sdjwt finds each one's concealed ancestors
// (RFC 9901 §4.2.6, §7.2) under the payload's _sd_alg.
func requireParentsSelected(payload map[string]interface{}, all, selected []string) error {
	r, err := recreate(payload, all)
	if err != nil {
		return err
	}
	chosen := make(map[string]bool, len(selected))
	for _, d := range selected {
		chosen[d] = true
	}
	var refusal *ParentDisclosureError
	listed := map[string]bool{}
	for _, d := range selected {
		h, err := josesdjwt.DigestWith(d, r.Alg)
		if err != nil {
			return err
		}
		ancestors, ok := r.Ancestors(h)
		if !ok {
			continue // not the credential's; ParseJOSECredential refuses it
		}
		// Innermost first, each listed once.
		for i := len(ancestors) - 1; i >= 0; i-- {
			p := ancestors[i].Encoded
			if chosen[p] || listed[p] {
				continue
			}
			listed[p] = true
			if refusal == nil {
				refusal = &ParentDisclosureError{Disclosure: d}
			}
			refusal.Missing = append(refusal.Missing, p)
		}
	}
	if refusal != nil {
		return refusal
	}
	return nil
}

// recreate reads the Issuer-signed payload with the credential's own
// disclosures through jose/sdjwt, under the payload's _sd_alg (sha-256 when
// absent). The credential was parsed or built under the same rules, so an
// error here means the payload or disclosures changed since.
func recreate(payload map[string]interface{}, disclosures []string) (*josesdjwt.Recreated, error) {
	alg := sdjwt.DefaultHashAlgorithm
	if v, ok := payload["_sd_alg"].(string); ok {
		alg = v
	}
	given := make([]josesdjwt.Disclosure, 0, len(disclosures))
	for _, d := range disclosures {
		if d != "" {
			given = append(given, josesdjwt.Disclosure{Encoded: d})
		}
	}
	r, err := josesdjwt.RecreateWithOptions(payload, given, josesdjwt.RecreateOptions{Algorithms: []string{alg}})
	if err != nil {
		return nil, fmt.Errorf("read the credential's disclosures: %w", err)
	}
	return r, nil
}

// ErrParentDisclosureNotSelected is what a *ParentDisclosureError unwraps to.
var ErrParentDisclosureNotSelected = errors.New("a selected disclosure is inside a concealed claim whose disclosure is not selected")

// ParentDisclosureError is Present's refusal of a selection that holds
// disclosures without the disclosures of the concealed claims they are nested
// in. Disclosure is the first such selected disclosure. Missing lists every
// disclosure the selection lacks, as encoded disclosures, without repeats:
// Disclosure's chain first, innermost first, then those of later selected
// disclosures. An application can show the holder what adding them reveals
// and present again.
type ParentDisclosureError struct {
	Disclosure string
	Missing    []string
}

func (e *ParentDisclosureError) Error() string {
	labels := make([]string, len(e.Missing))
	for i, m := range e.Missing {
		labels[i] = disclosureLabel(m)
	}
	return fmt.Sprintf("disclosure %s is inside a concealed claim that is not selected; select %d more disclosure(s), %s, which reveals their other members",
		disclosureLabel(e.Disclosure), len(e.Missing), strings.Join(labels, ", "))
}

// Unwrap returns ErrParentDisclosureNotSelected, for errors.Is.
func (e *ParentDisclosureError) Unwrap() error { return ErrParentDisclosureNotSelected }

// disclosureLabel names the claim of an encoded disclosure for an error text.
func disclosureLabel(encoded string) string {
	d, err := josesdjwt.ParseDisclosure(encoded)
	switch {
	case err != nil:
		return "(unreadable)"
	case d.ArrayElement:
		return "(an array element)"
	}
	return fmt.Sprintf("%.64q", d.Name)
}
