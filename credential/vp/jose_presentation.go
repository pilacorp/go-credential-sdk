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

	"github.com/pilacorp/go-credential-sdk/credential/common/jsonmap"
	"github.com/pilacorp/go-credential-sdk/credential/common/jwt"
	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"golang.org/x/sync/errgroup"
)

// JOSEPresentation implements W3C VC 2.0 Securing Verifiable Presentations using JOSE (vc-jose-cose).
// In vc-jose-cose, the unsecured Verifiable Presentation is the unencoded JWS payload (flat,
// without the legacy "vp" wrapper claim), and the header carries typ: "vp+jwt".
type JOSEPresentation struct {
	signingInput string           // JWS header.payload (base64 encoded)
	payloadData  PresentationData // Unsecured VP as PresentationData
	signature    string           // JWS signature (if signed)
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

	// Transform embedded credentials into EnvelopedVerifiableCredential format per W3C vc-jose-cose § 3.1.2
	if len(vpc.VerifiableCredentials) > 0 {
		envelopedList := make([]interface{}, len(vpc.VerifiableCredentials))
		for i, cred := range vpc.VerifiableCredentials {
			if cred == nil {
				return nil, fmt.Errorf("credential at index %d is nil", i)
			}
			serialized, err := cred.Serialize()
			if err != nil {
				return nil, fmt.Errorf("failed to serialize credential at index %d: %w", i, err)
			}
			if credStr, ok := serialized.(string); ok {
				envelopedList[i] = map[string]interface{}{
					"@context": []interface{}{"https://www.w3.org/ns/credentials/v2"},
					"type":     []interface{}{"EnvelopedVerifiableCredential"},
					"id":       fmt.Sprintf("data:application/vc+jwt,%s", credStr),
				}
			} else {
				envelopedList[i] = serialized
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
	jwt.SetIssuedAt(payloadData, time.Now())

	// Resolve the Verification Method and derive the JOSE alg
	vm, kid, err := verificationmethod.ResolveSigningVM(context.Background(), vpc.Holder,
		"authentication", options.verificationMethodKey, options.resolver)
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

	// Per W3C vc-jose-cose Section 3.1.2: typ MUST/SHOULD be "vp+jwt"
	header := map[string]interface{}{
		"typ": "vp+jwt",
		"alg": alg,
		"kid": kid,
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
	if typ != "vp+jwt" && typ != "application/vp+jwt" {
		return nil, fmt.Errorf("invalid typ header for JOSEPresentation: got %q, want 'vp+jwt' or 'application/vp+jwt'", typ)
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

	signingInput := headerEncoded + "." + payloadEncoded

	e := &JOSEPresentation{
		signingInput: signingInput,
		payloadData:  PresentationData(payloadMap),
		signature:    signature,
	}

	return e, e.executeOptions(opts...)
}

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
	if err := j.applyChallengeDomain(options); err != nil {
		return err
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
	return "JOSE"
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
			serialized, err := j.Serialize()
			if err != nil {
				return fmt.Errorf("serialize presentation: %w", err)
			}

			verifier := jwt.NewJWTVerifier(options.resolver)
			if err := verifier.VerifyJWT(serialized.(string)); err != nil {
				return fmt.Errorf("verify proof: %w", err)
			}
			// exp and nbf bound the signature, not the presentation, so they
			// belong to this check and not to the optional expiry check on
			// validFrom/validUntil.
			if err := jwt.CheckTimeClaims(j.payloadData, time.Now()); err != nil {
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

func (j *JOSEPresentation) applyChallengeDomain(options *presentationOptions) error {
	if options.challenge == "" && options.domain == "" {
		return nil
	}
	if j.payloadData == nil {
		return fmt.Errorf("presentation has no payload data to update")
	}
	if options.challenge != "" {
		j.payloadData["nonce"] = options.challenge
	}
	if options.domain != "" {
		j.payloadData["aud"] = options.domain
	}
	payloadJSON, err := json.Marshal(j.payloadData)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}
	header, _, _ := strings.Cut(j.signingInput, ".")
	j.signingInput = header + "." + base64.RawURLEncoding.EncodeToString(payloadJSON)
	j.signature = ""
	return nil
}

func (j *JOSEPresentation) checkChallengeAndDomain(options *presentationOptions) error {
	if options.expectedChallenge != "" {
		nonce, _ := j.payloadData["nonce"].(string)
		if nonce != options.expectedChallenge {
			return fmt.Errorf("nonce %q does not match expected challenge %q", nonce, options.expectedChallenge)
		}
	}
	if options.expectedDomain != "" && !audContains(j.payloadData["aud"], options.expectedDomain) {
		return fmt.Errorf("aud %v does not match expected domain %q", j.payloadData["aud"], options.expectedDomain)
	}
	return nil
}

