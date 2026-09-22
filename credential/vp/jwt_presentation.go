package vp

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/pilacorp/go-credential-sdk/credential/common/dto"
	"github.com/pilacorp/go-credential-sdk/credential/common/jsonmap"
	"github.com/pilacorp/go-credential-sdk/credential/common/jwt"
	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
)

type JWTPresentation struct {
	signingInput string                 // JWT header.payload (base64 encoded)
	payloadData  PresentationData       // Parsed payload as PresentationData
	jwtClaims    map[string]interface{} // Top-level JWT claims (iss, aud, nonce, ...)
	signature    string                 // JWT signature (if signed)
	signingKey   jwt.SigningKey         // Verification method the header names; zero for a parsed presentation
}

var _ Presentation = (*JWTPresentation)(nil)

func NewJWTPresentation(vpc PresentationContents, opts ...PresentationOpt) (*JWTPresentation, error) {
	// Convert PresentationContents to PresentationData
	m, err := serializePresentationContents(&vpc)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize presentation contents: %w", err)
	}

	payloadData := PresentationData(m)

	// Extract other claims from presentationContents
	otherClaims := map[string]interface{}{}
	if vpc.Holder != "" {
		otherClaims["iss"] = vpc.Holder
		otherClaims["sub"] = vpc.Holder
	}
	if !vpc.ValidUntil.IsZero() {
		otherClaims["exp"] = vpc.ValidUntil.Unix()
	}
	if !vpc.ValidFrom.IsZero() {
		otherClaims["iat"] = vpc.ValidFrom.Unix()
		otherClaims["nbf"] = vpc.ValidFrom.Unix()
	}
	if vpc.ID != "" {
		otherClaims["jti"] = vpc.ID
	}

	// Build payload with vp claim and other claims
	payload := map[string]interface{}{
		"vp": payloadData,
	}
	// Add other claims to payload
	for key, value := range otherClaims {
		payload[key] = value
	}

	options := getOptions(opts...)

	// Challenge/domain map to the standard JWT claims used by OpenID4VP and
	// VC-JWT: nonce (replay protection) and aud (intended verifier).
	if options.challenge != "" {
		payload["nonce"] = options.challenge
	}
	if options.domain != "" {
		payload["aud"] = options.domain
	}

	// Resolve the VM so alg reflects the key it actually holds, and so a kid
	// that does not exist or is not granted authentication is caught here.
	signingKey, err := jwt.ResolveSigningKey(context.Background(), vpc.Holder, "authentication",
		options.verificationMethodKey, options.resolver)
	if err != nil {
		return nil, err
	}

	header := map[string]interface{}{
		"typ": "JWT",
		"alg": signingKey.Alg,
		"kid": signingKey.ID,
	}

	// Encode header and payload
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

	// Create signing input (header.payload)
	signingInput := headerEncoded + "." + payloadEncoded

	e := &JWTPresentation{
		signingInput: signingInput,
		payloadData:  payloadData,
		jwtClaims:    payload,
		signature:    "",
		signingKey:   signingKey,
	}

	// Return JWTPresentation
	return e, e.executeOptions(opts...)
}

func ParseJWTPresentation(rawJWT string, opts ...PresentationOpt) (*JWTPresentation, error) {
	if !isJWTPresentation(rawJWT) {
		return nil, fmt.Errorf("invalid JWT format")
	}

	// prevent " from marshalling to json
	rawJWT = strings.Trim(rawJWT, "\"")

	// Split JWT into parts
	parts := strings.Split(rawJWT, ".")

	// Extract the payload and header
	headerEncoded := parts[0]
	payloadEncoded := parts[1]
	signature := ""
	if len(parts) == 3 {
		signature = parts[2]
	}

	// Decode the payload and header
	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadEncoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}

	var payloadMap map[string]interface{}
	err = json.Unmarshal(payloadBytes, &payloadMap)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal payload: %w", err)
	}

	// Store the vp claim in payload as payloadData
	vpData, ok := payloadMap["vp"]
	if !ok {
		return nil, fmt.Errorf("vp claim not found in JWT payload")
	}

	vpMap, ok := vpData.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("vp claim is not a valid JSON object")
	}

	// Create signing input (header.payload)
	signingInput := headerEncoded + "." + payloadEncoded

	e := &JWTPresentation{
		signingInput: signingInput,
		payloadData:  PresentationData(vpMap),
		jwtClaims:    payloadMap,
		signature:    signature,
	}

	return e, e.executeOptions(opts...)
}

// Deprecated: prefer AddProofByProvider with a signer provider; this legacy signing helper may be removed in a future release.
func (j *JWTPresentation) AddProof(priv string, opts ...PresentationOpt) error {
	defaultSigner, err := signer.NewDefaultProvider(priv)
	if err != nil {
		return fmt.Errorf("failed to create default signer: %w", err)
	}
	return j.AddProofByProvider(defaultSigner, opts...)
}

func (j *JWTPresentation) AddProofByProvider(provider signer.SignerProvider, opts ...PresentationOpt) error {
	if provider == nil {
		return fmt.Errorf("signer provider cannot be nil")
	}
	o := getOptions(opts...)
	if err := rejectBuildTimeOptions(o, false); err != nil {
		return err
	}

	// WithChallenge/WithDomain may be given at signing time, as with JSON
	// presentations; they overwrite nonce/aud and the payload is re-encoded.
	if err := j.applyChallengeDomain(o); err != nil {
		return err
	}
	if err := j.executeOptions(signingOptions(opts)...); err != nil {
		return err
	}

	digest := sha256.Sum256([]byte(j.signingInput))
	raw, err := provider.Sign(digest[:])
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

func (j *JWTPresentation) GetSigningInput() ([]byte, error) {
	return []byte(j.signingInput), nil
}

// AddCustomProof attaches a signature made outside the SDK over GetSigningInput.
// It is held to the same check as every signing path: the signature must be
// 64-byte r||s and verify against the verification method the header names.
func (j *JWTPresentation) AddCustomProof(proof *dto.Proof, opts ...PresentationOpt) error {
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

func (j *JWTPresentation) Verify(opts ...PresentationOpt) error {
	opts = append(opts, WithVerifyProof())

	return j.executeOptions(opts...)
}

func (j *JWTPresentation) Serialize() (interface{}, error) {
	if j.signature != "" {
		// Signed JWT
		return j.signingInput + "." + j.signature, nil
	} else {
		// Unsigned JWT
		return j.signingInput, nil
	}
}

func (j *JWTPresentation) GetContents() ([]byte, error) {
	return (*jsonmap.JSONMap)(&j.payloadData).ToJSON()
}

func (j *JWTPresentation) GetType() string {
	return "JWT"
}

func (j *JWTPresentation) ExtractField(path string) interface{} {
	return extractFieldFromMap(j.payloadData, path)
}

func (j *JWTPresentation) executeOptions(opts ...PresentationOpt) error {
	options := getOptions(opts...)

	if options.isValidateVC {
		if err := verifyCredentials(PresentationData(j.payloadData), options); err != nil {
			return fmt.Errorf("failed to verify presentation: %w", err)
		}
	}

	if options.isCheckExpiration {
		if err := checkExpiration(PresentationData(j.payloadData)); err != nil {
			return fmt.Errorf("failed to check expiration: %w", err)
		}
	}

	if options.isVerifyProof {
		serialized, err := j.Serialize()
		if err != nil {
			return fmt.Errorf("failed to serialize presentation: %w", err)
		}

		verifier := jwt.NewJWTVerifier(options.resolver)
		err = verifier.VerifyJWT(serialized.(string))
		if err != nil {
			return fmt.Errorf("failed to verify presentation: %w", err)
		}
		if err := j.checkChallengeAndDomain(options); err != nil {
			return fmt.Errorf("failed to verify presentation: %w", err)
		}
	}

	return nil
}

// applyChallengeDomain writes options.challenge/domain into the nonce/aud
// claims and re-encodes the payload half of signingInput. No-op when neither
// is set.
func (j *JWTPresentation) applyChallengeDomain(options *presentationOptions) error {
	if options.challenge == "" && options.domain == "" {
		return nil
	}
	if j.jwtClaims == nil {
		return fmt.Errorf("presentation has no JWT claims to update")
	}
	if options.challenge != "" {
		j.jwtClaims["nonce"] = options.challenge
	}
	if options.domain != "" {
		j.jwtClaims["aud"] = options.domain
	}
	payloadJSON, err := json.Marshal(j.jwtClaims)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}
	header, _, _ := strings.Cut(j.signingInput, ".")
	j.signingInput = header + "." + base64.RawURLEncoding.EncodeToString(payloadJSON)
	j.signature = ""
	return nil
}

// checkChallengeAndDomain enforces WithExpectedChallenge / WithExpectedDomain
// against the nonce and aud claims. Runs after signature verification, so the
// values compared are the signed ones.
func (j *JWTPresentation) checkChallengeAndDomain(options *presentationOptions) error {
	if options.expectedChallenge != "" {
		nonce, _ := j.jwtClaims["nonce"].(string)
		if nonce != options.expectedChallenge {
			return fmt.Errorf("nonce %q does not match expected challenge %q", nonce, options.expectedChallenge)
		}
	}
	if options.expectedDomain != "" && !audContains(j.jwtClaims["aud"], options.expectedDomain) {
		return fmt.Errorf("aud %v does not match expected domain %q", j.jwtClaims["aud"], options.expectedDomain)
	}
	return nil
}

// audContains reports whether the aud claim (a string or array of strings per
// RFC 7519 §4.1.3) includes domain.
func audContains(aud interface{}, domain string) bool {
	switch v := aud.(type) {
	case string:
		return v == domain
	case []interface{}:
		for _, item := range v {
			if s, ok := item.(string); ok && s == domain {
				return true
			}
		}
	case []string:
		for _, s := range v {
			if s == domain {
				return true
			}
		}
	}
	return false
}

// rejectBuildTimeOptions refuses options a signing call can no longer apply:
// the header's kid always; nonce/aud too when the signature was made outside
// the SDK (signedOutside), since it already covers the signing input.
func rejectBuildTimeOptions(o *presentationOptions, signedOutside bool) error {
	if o.verificationMethodKey != "" {
		return fmt.Errorf("WithVerificationMethodKey cannot be applied when signing a JWT: the header's kid was fixed when the token was built — pass the option to NewJWTPresentation")
	}
	if signedOutside && (o.challenge != "" || o.domain != "") {
		return fmt.Errorf("WithChallenge / WithDomain cannot be applied by AddCustomProof: the signature already covers the signing input — pass them to NewJWTPresentation before GetSigningInput, or sign with AddProofByProvider")
	}
	return nil
}
