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
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"golang.org/x/sync/errgroup"
)

// JOSECredential implements W3C VC 2.0 Securing Verifiable Credentials using JOSE (vc-jose-cose).
// In vc-jose-cose, the unsecured Verifiable Credential is the unencoded JWS payload (flat,
// without the legacy "vc" wrapper claim), and the header carries typ: "vc+jwt".
type JOSECredential struct {
	signingInput string         // JWS header.payload (base64 encoded)
	payloadData  CredentialData // Unsecured VC as CredentialData
	signature    string         // JWS signature (if signed)
	disclosures  []string       // Optional SD-JWT disclosures
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

	// SD-JWT disclosure support if requested
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
	disclosures = append(disclosures, options.sdDisclosures...)

	// Per W3C vc-jose-cose Section 1.1.2.1:
	// "The JWT Claim Names vc and vp MUST NOT be present in any JWT Claims Set that
	// comprises a verifiable credential or a verifiable presentation."
	delete(vcMap, "vc")
	delete(vcMap, "vp")

	// Without iat the verifier has no signing time to compare a soft revocation
	// against, and would have to guess one from validFrom — a different fact.
	jwt.SetIssuedAt(vcMap, time.Now())

	payloadData := CredentialData(vcMap)

	// Resolve the Verification Method and derive the JOSE alg
	vm, kid, err := verificationmethod.ResolveSigningVM(context.Background(), vcc.Issuer,
		"assertionMethod", options.verificationMethodKey, options.resolver)
	if err != nil {
		return nil, fmt.Errorf("resolve verification method: %w", err)
	}
	kind, ok := verificationmethod.VMKeyKind(vm)
	if !ok {
		return nil, fmt.Errorf("verification method %q has an unrecognized key type", kid)
	}
	alg, err := jwt.AlgForKeyKind(kind)
	if err != nil {
		return nil, fmt.Errorf("verification method %q: %w", kid, err)
	}

	// typ names the securing mechanism, so it follows the disclosures rather
	// than being fixed: vc-jose-cose says typ SHOULD be "vc+jwt" when securing
	// with JWS, and "vc+sd-jwt" when securing with SD-JWT. A verifier routes on
	// this, and one told "vc+jwt" will parse the token as plain JWS and choke on
	// the disclosures trailing the signature.
	header := map[string]interface{}{
		"typ": TypeVCJWT,
		"alg": alg,
		"kid": kid,
	}
	if len(disclosures) > 0 {
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
	}

	return e, e.executeOptions(opts...)
}

// ParseJOSECredential parses a W3C vc-jose-cose (vc+jwt) token.
func ParseJOSECredential(rawJWT string, opts ...CredentialOpt) (*JOSECredential, error) {
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

	vcMap := payloadMap
	if len(disclosures) > 0 {
		processed, err := sdjwt.Reconstruct(vcMap, disclosures, true)
		if err != nil {
			return nil, fmt.Errorf("failed to reconstruct SD-JWT payload: %w", err)
		}
		vcMap = processed
	}

	// A signature proves who produced these bytes, not that the bytes are a
	// credential. The typ header already promised one, so hold the payload to
	// that promise here — otherwise a v1 document, a presentation, or a payload
	// with no @context at all verifies to nil and is handed back as a VC.
	// Checked after reconstruction, so a disclosed property still counts.
	if err := requireJOSECredential(CredentialData(vcMap)); err != nil {
		return nil, err
	}

	signingInput := headerEncoded + "." + payloadEncoded

	e := &JOSECredential{
		signingInput: signingInput,
		payloadData:  CredentialData(vcMap),
		signature:    signature,
		disclosures:  disclosures,
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
// A vc+jwt carrying disclosures is still read: tokens issued before the SD-JWT
// typ was written verify fine, and the shape is carried by the disclosures
// rather than by the label.
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

	jwtSigner := jwt.NewJWTSigner(signerProvider)
	signature, err := jwtSigner.SignString(j.signingInput)
	if err != nil {
		return fmt.Errorf("failed to sign signing input: %w", err)
	}

	j.signature = signature
	if err := j.executeOptions(opts...); err != nil {
		j.signature = ""
		return err
	}
	return nil
}

// Deprecated: prefer AddProofByProvider with a signer provider; this legacy signing helper may be removed in a future release.
func (j *JOSECredential) GetSigningInput() ([]byte, error) {
	return []byte(j.signingInput), nil
}

// Deprecated: prefer AddProofByProvider with a signer provider; this legacy signing helper may be removed in a future release.
func (j *JOSECredential) AddCustomProof(proof *dto.Proof, opts ...CredentialOpt) error {
	if proof == nil {
		return fmt.Errorf("proof cannot be nil")
	}
	if len(proof.Signature) == 0 {
		return fmt.Errorf("proof signature cannot be empty")
	}

	// Attach the signature before running the options, because WithVerifyProof
	// is one of them and it reads j.signature: running the options first made it
	// report "credential is not signed" about the very signature being attached.
	// A rejected proof is rolled back, so a failed call leaves the credential as
	// it found it.
	previous := j.signature
	j.signature = base64.RawURLEncoding.EncodeToString(jwt.TrimRecoveryByte(proof.Signature))
	if err := j.executeOptions(opts...); err != nil {
		j.signature = previous
		return err
	}
	return nil
}

func (j *JOSECredential) Verify(opts ...CredentialOpt) error {
	opts = append(opts, WithVerifyProof())
	return j.executeOptions(opts...)
}

func (j *JOSECredential) Serialize() (any, error) {
	base := j.signingInput
	if j.signature != "" || len(j.disclosures) > 0 {
		base = base + "." + j.signature
	}

	if len(j.disclosures) == 0 {
		return base, nil
	}

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

func (j *JOSECredential) DecodedDisclosures() ([]sdjwt.DecodedDisclosure, error) {
	return sdjwt.DecodeDisclosures(j.disclosures)
}

func (j *JOSECredential) Present(selectedDisclosures []string) (Credential, error) {
	if j.signature == "" {
		return nil, fmt.Errorf("cannot present an unsigned credential")
	}
	issuerJWT := j.signingInput + "." + j.signature
	return ParseJOSECredential(sdjwt.BuildSDJWTPresentation(issuerJWT, selectedDisclosures))
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
			if err := jwt.CheckTimeClaims(j.payloadData, time.Now()); err != nil {
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
