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

type JWTHeaders map[string]interface{}

type JWTCredential struct {
	signingInput string                 // JWT header.payload (base64 encoded)
	payloadData  CredentialData         // The vc claim, parsed as CredentialData
	jwtClaims    map[string]interface{} // Top-level JWT claims (iss, sub, exp, nbf, iat, jti)
	signature    string                 // JWT signature (if signed)
	disclosures  []string               // Optional SD-JWT disclosures (when issuing/holding SD-JWT)
	disclosable  bool                   // Payload carries _sd digests, even if this holder reveals none
	signingKey   jwt.SigningKey         // Verification method the header names; zero for a parsed credential
}

var _ Credential = (*JWTCredential)(nil)

func NewJWTCredential(vcc CredentialContents, opts ...CredentialOpt) (*JWTCredential, error) {
	m, err := serializeCredentialContents(&vcc)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize credential contents: %w", err)
	}

	vcMap := normalizeCredentialData(m)
	options := getOptions(opts...)

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

	// Same rule the parse side applies: nothing outside credentialSubject may be
	// disclosable. Reachable here through WithSDSelectivePaths naming a path
	// outside the subject, or WithSDDecoyDigests with a root path. The subject
	// itself is exempt — hiding claims in there is the feature.
	if err := requireDisclosableAtTopLevel(vcMap, true); err != nil {
		return nil, err
	}

	// Reconstruct deep-copies, so this validates without touching what gets
	// signed.
	if _, rerr := sdjwt.Reconstruct(vcMap, disclosures, true); rerr != nil {
		return nil, fmt.Errorf("invalid SD-JWT disclosures: %w", rerr)
	}

	// See NewJOSECredential: read from the payload, the same question
	// ParseJWTCredential asks of the same bytes, so a decoys-only credential does
	// not serialize one way at build time and another after a round-trip.
	_, disclosable := vcMap["_sd_alg"]

	payloadData := CredentialData(vcMap)

	otherClaims := map[string]interface{}{}
	if vcc.Issuer != "" {
		otherClaims["iss"] = vcc.Issuer
	}
	if len(vcc.Subject) > 0 && vcc.Subject[0].ID != "" {
		otherClaims["sub"] = vcc.Subject[0].ID
	}
	if !vcc.ValidUntil.IsZero() {
		otherClaims["exp"] = vcc.ValidUntil.Unix()
	}
	if !vcc.ValidFrom.IsZero() {
		otherClaims["iat"] = vcc.ValidFrom.Unix()
		otherClaims["nbf"] = vcc.ValidFrom.Unix()
	}
	if vcc.ID != "" {
		otherClaims["jti"] = vcc.ID
	}

	payload := map[string]interface{}{"vc": payloadData}
	for key, value := range otherClaims {
		payload[key] = value
	}

	// Resolve the VM so alg reflects the key it actually holds, and so a kid
	// that does not exist or is not granted assertionMethod is caught here.
	signingKey, err := jwt.ResolveSigningKey(context.Background(), vcc.Issuer, "assertionMethod",
		options.verificationMethodKey, options.resolver)
	if err != nil {
		return nil, err
	}

	header := map[string]interface{}{
		"typ": "JWT",
		"alg": signingKey.Alg,
		"kid": signingKey.ID,
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal header: %w", err)
	}
	headerEncoded := base64.RawURLEncoding.EncodeToString(headerJSON)

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}
	payloadEncoded := base64.RawURLEncoding.EncodeToString(payloadJSON)

	signingInput := headerEncoded + "." + payloadEncoded

	e := &JWTCredential{
		signingInput: signingInput,
		payloadData:  payloadData,
		jwtClaims:    otherClaims,
		signature:    "",
		disclosures:  disclosures,
		disclosable:  disclosable,
		signingKey:   signingKey,
	}

	return e, e.executeOptions(opts...)
}

func ParseJWTCredential(rawJWT string, opts ...CredentialOpt) (*JWTCredential, error) {
	rawJWT = strings.TrimSpace(strings.Trim(rawJWT, "\""))

	var issuerJWT string
	var disclosures []string

	if sdjwt.IsSDJWT(rawJWT) {
		parsed, err := sdjwt.Parse(rawJWT)
		if err != nil {
			return nil, fmt.Errorf("failed to parse SD-JWT: %w", err)
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

	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadEncoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}

	var payloadMap map[string]interface{}
	err = json.Unmarshal(payloadBytes, &payloadMap)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal payload: %w", err)
	}

	vcData, ok := payloadMap["vc"]
	if !ok {
		return nil, fmt.Errorf("vc claim not found in JWT payload")
	}

	vcMap, ok := vcData.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("vc claim is not a valid JSON object")
	}

	// The call the 2.0 parser has had and this one was missing, which is why the
	// revocation bypass reached the released path: nothing outside
	// credentialSubject may be disclosable. A VC 1.1 token has no media type to
	// contradict its own payload — it types itself "JWT" either way — so the
	// subject stays exempt here.
	if err := requireDisclosableAtTopLevel(vcMap, true); err != nil {
		return nil, err
	}

	signedVC := vcMap
	// Same gate as ParseJOSECredential, and for the same reason: Reconstruct is
	// what removes the _sd arrays, so a holder revealing nothing used to leave
	// them visible in the document the caller reads.
	//
	// There is no media type to read here — a VC 1.1 token types itself "JWT"
	// whether or not it is selectively disclosed — so the combined format is the
	// only signal that does not depend on _sd_alg, which RFC 9901 § 4.1.1 leaves
	// optional.
	_, hasSDAlg := vcMap["_sd_alg"]
	disclosable := hasSDAlg || sdjwt.IsSDJWT(rawJWT)
	if disclosable || len(disclosures) > 0 {
		processed, rerr := sdjwt.Reconstruct(vcMap, disclosures, true)
		if rerr != nil {
			return nil, fmt.Errorf("failed to reconstruct SD-JWT payload: %w", rerr)
		}
		vcMap = processed
	}

	// The claims a verifier decides on have to be inside the signature, not
	// inside a disclosure the holder controls. ParseJOSECredential enforces the
	// same rule on the 2.0 path. Reconstruct deep-copies, so signedVC is still
	// exactly what the signature covered.
	if err := requireSecuredClaimsSigned(signedVC, vcMap); err != nil {
		return nil, fmt.Errorf("invalid SD-JWT credential: %w", err)
	}

	signingInput := headerEncoded + "." + payloadEncoded

	e := &JWTCredential{
		signingInput: signingInput,
		payloadData:  CredentialData(vcMap),
		jwtClaims:    payloadMap,
		signature:    signature,
		disclosures:  disclosures,
		disclosable:  disclosable,
	}

	return e, e.executeOptions(opts...)
}

// Deprecated: prefer AddProofByProvider with a signer provider; this legacy signing helper may be removed in a future release.
func (j *JWTCredential) AddProof(priv string, opts ...CredentialOpt) error {
	defaultSigner, err := signer.NewDefaultProvider(priv)
	if err != nil {
		return fmt.Errorf("failed to create default signer: %w", err)
	}
	return j.AddProofByProvider(defaultSigner, opts...)
}

func (j *JWTCredential) AddProofByProvider(signerProvider signer.SignerProvider, opts ...CredentialOpt) error {
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
	signature, err := j.signingKey.Accept(j.signingInput, raw)
	if err != nil {
		return err
	}
	j.signature = signature
	return nil
}

func (j *JWTCredential) GetSigningInput() ([]byte, error) {
	return []byte(j.signingInput), nil
}

// AddCustomProof attaches a signature made outside the SDK over GetSigningInput.
// It is held to the same check as every signing path: the signature must be
// 64-byte r||s and verify against the verification method the header names.
func (j *JWTCredential) AddCustomProof(proof *dto.Proof, opts ...CredentialOpt) error {
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

	signature, err := j.signingKey.Accept(j.signingInput, proof.Signature)
	if err != nil {
		return err
	}
	j.signature = signature
	return nil
}

func (j *JWTCredential) Verify(opts ...CredentialOpt) error {
	opts = append(opts, WithVerifyProof())
	return j.executeOptions(opts...)
}

func (j *JWTCredential) Serialize() (any, error) {
	base := j.signingInput
	if j.signature != "" || len(j.disclosures) > 0 {
		base = base + "." + j.signature
	}

	if !j.disclosable {
		return base, nil
	}

	// See JOSECredential.Serialize: the terminator is what marks the token as an
	// SD-JWT, and the digests are in the payload whether or not this holder
	// reveals anything.
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

// Hash returns the SHA-256 hash (hex-encoded) of the full serialized JWT string
// (header.payload.signature, plus disclosures for SD-JWT). No canonicalization is
// needed: the serialized JWT is a fixed string, so the hash is deterministic.
// The credential must be signed before hashing.
func (j *JWTCredential) Hash() (string, error) {
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

func (j *JWTCredential) GetContents() ([]byte, error) {
	return (*jsonmap.JSONMap)(&j.payloadData).ToJSON()
}

func (j *JWTCredential) GetType() string {
	return "JWT"
}

func (j *JWTCredential) ExtractField(path string) any {
	if j.payloadData == nil {
		return nil
	}
	return extractFieldFromMap(j.payloadData, path)
}

// DecodedDisclosures returns the credential's disclosures decoded (field name,
// value, salt) so a Holder can choose which to present.
func (j *JWTCredential) DecodedDisclosures() ([]sdjwt.DecodedDisclosure, error) {
	return sdjwt.DecodeDisclosures(j.disclosures)
}

// Present returns a new SD-JWT credential revealing only selectedDisclosures
// (a subset of the disclosure strings), keeping the issuer's signature. Holders
// use it to disclose a subset to a Verifier.
func (j *JWTCredential) Present(selectedDisclosures []string) (Credential, error) {
	if j.signature == "" {
		return nil, fmt.Errorf("cannot present an unsigned credential")
	}
	issuerJWT := j.signingInput + "." + j.signature

	// See JOSECredential.Present: a credential with nothing disclosable has no
	// subset to choose, and BuildSDJWTPresentation would hand back the same JWT
	// under an SD-JWT terminator, changing its bytes and its Hash.
	if len(j.disclosures) == 0 {
		return nil, fmt.Errorf("credential carries no disclosures; nothing to present selectively")
	}

	return ParseJWTCredential(sdjwt.BuildSDJWTPresentation(issuerJWT, selectedDisclosures))
}

func (j *JWTCredential) executeOptions(opts ...CredentialOpt) error {
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
			issuerJWT := j.signingInput + "." + j.signature

			verifier := jwt.NewJWTVerifier(options.resolver)
			if err := verifier.VerifyJWT(issuerJWT); err != nil {
				return fmt.Errorf("verify proof: %w", err)
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return fmt.Errorf("credential verification failed: %w", err)
	}

	if options.isCheckExpiration {
		// Two time windows, in two places. validFrom/validUntil live inside the
		// vc claim and describe the credential; exp/nbf live beside it, at the top
		// level, and describe the token. This path writes both — exp and nbf are
		// derived from ValidUntil and ValidFrom at signing — so checking only the
		// inner pair let a token past its own exp verify.
		//
		// Unlike the vc+jwt path, which enforces exp and nbf on every Verify,
		// this stays behind the option: credentials already issued carry an exp
		// mirroring validUntil, and making it unconditional would start refusing
		// them on a plain Verify that accepts them today.
		//
		// The credential's own window is reported first, so a credential that was
		// already refused keeps the message it had; the RFC 7519 wording appears
		// only for tokens whose exp or nbf nothing else covers.
		if err := checkExpiration(j.payloadData); err != nil {
			return fmt.Errorf("failed to check expiration: %w", err)
		}
		if err := jwtutil.CheckTimeClaims(j.jwtClaims, time.Now()); err != nil {
			return fmt.Errorf("failed to check expiration: %w", err)
		}
	}

	return nil
}

// rejectBuildTimeOptions refuses options that only NewJWTCredential applies —
// the header's kid and the SD-JWT options — so a signing call does not drop
// them silently.
func rejectBuildTimeOptions(o *credentialOptions) error {
	if o.verificationMethodKey != "" {
		return fmt.Errorf("WithVerificationMethodKey cannot be applied when signing a JWT: the header's kid was fixed when the token was built — pass the option to NewJWTCredential")
	}
	if o.hasSDOptions() {
		return fmt.Errorf("SD-JWT options cannot be applied when signing: the disclosures were fixed when the token was built — pass them to NewJWTCredential")
	}
	return nil
}
