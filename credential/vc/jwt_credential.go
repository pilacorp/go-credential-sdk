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
	signingKey   jwt.SigningKey         // Verification method the header names; zero for a parsed credential
}

var _ Credential = (*JWTCredential)(nil)

func NewJWTCredential(vcc CredentialContents, opts ...CredentialOpt) (*JWTCredential, error) {
	options := getOptions(opts...)

	// Selective disclosure is issued as vc+sd-jwt only (#100). A VC 1.1 JWT types
	// itself "JWT", so a verifier outside this SDK had no way to tell it carried
	// disclosures. Refused before anything is built, and before the DID is
	// resolved, so a call that cannot succeed costs no network round trip.
	if options.hasSDOptions() {
		return nil, fmt.Errorf("NewJWTCredential: %w", ErrSDJWTRequiresJOSE)
	}

	m, err := serializeCredentialContents(&vcc)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize credential contents: %w", err)
	}

	vcMap := normalizeCredentialData(m)

	// The option check misses contents that already carry digests: a caller who
	// ran sdjwt.BuildDisclosures and put the processed claims into the contents
	// passes no SD option at all. Building it would produce a JWT carrying
	// digests that ParseJWTCredential then refuses, so it is refused here.
	if carriesSDJWT(vcMap) {
		return nil, fmt.Errorf("NewJWTCredential: contents carry SD-JWT digests: %w", ErrSDJWTRequiresJOSE)
	}

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
		signingKey:   signingKey,
	}

	return e, e.executeOptions(opts...)
}

func ParseJWTCredential(rawJWT string, opts ...CredentialOpt) (*JWTCredential, error) {
	rawJWT = strings.TrimSpace(strings.Trim(rawJWT, "\""))

	// base64url has no "~", so a valid JWT never contains one: a "~" means the
	// SD-JWT combined form. That includes a plain JWT someone appended a "~" to,
	// which used to parse as the plain JWT; there is no reason left to accept it.
	if strings.Contains(rawJWT, "~") {
		return nil, fmt.Errorf("ParseJWTCredential: token is in SD-JWT combined form: %w", ErrSDJWTRequiresJOSE)
	}
	if !isJWTCredential(rawJWT) {
		return nil, fmt.Errorf("invalid JWT format")
	}

	parts := strings.Split(rawJWT, ".")
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

	// Digests in the signed payload make it an SD-JWT whether or not any
	// disclosure came with it, so this is checked on the payload, not only on
	// the "~" above.
	if carriesSDJWT(payloadMap) {
		return nil, fmt.Errorf("ParseJWTCredential: payload carries SD-JWT digests: %w", ErrSDJWTRequiresJOSE)
	}

	vcData, ok := payloadMap["vc"]
	if !ok {
		return nil, fmt.Errorf("vc claim not found in JWT payload")
	}

	vcMap, ok := vcData.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("vc claim is not a valid JSON object")
	}

	signingInput := headerEncoded + "." + payloadEncoded

	e := &JWTCredential{
		signingInput: signingInput,
		payloadData:  CredentialData(vcMap),
		jwtClaims:    payloadMap,
		signature:    signature,
	}

	return e, e.executeOptions(opts...)
}

// carriesSDJWT reports whether a VC 1.1 document or JWT payload carries any
// SD-JWT machinery: _sd_alg, an _sd array, or an array element {"...": digest},
// at any depth.
//
// _sd_alg is looked for at the top of m and inside its vc claim. This SDK wrote
// it under vc; RFC 9901 § 4.1.1 puts it at the top of the payload, which is where
// another implementation's token would carry it. It is not relied on alone,
// because the same section makes it optional: the digests themselves are the
// signal that is always there and always signed.
func carriesSDJWT(m map[string]interface{}) bool {
	if _, ok := m["_sd_alg"]; ok {
		return true
	}
	if vc, ok := m["vc"].(map[string]interface{}); ok {
		if _, ok := vc["_sd_alg"]; ok {
			return true
		}
	}
	return carriesSDMachinery(m)
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
	if j.signature == "" {
		return j.signingInput, nil
	}
	return j.signingInput + "." + j.signature, nil
}

// Hash returns the SHA-256 hash (hex-encoded) of the full serialized JWT string
// (header.payload.signature). No canonicalization is
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

// DecodedDisclosures reports the credential's disclosures. A VC 1.1 JWT carries
// none (#100), so it always returns an empty, non-nil slice and no error — the
// same answer it gave for a plain JWT before, so a caller that asks it of every
// credential keeps working.
//
// Deprecated: selective disclosure is no longer supported on VC 1.1 JWT. Use
// JOSECredential.DecodedDisclosures on a vc+sd-jwt credential.
func (j *JWTCredential) DecodedDisclosures() ([]sdjwt.DecodedDisclosure, error) {
	return []sdjwt.DecodedDisclosure{}, nil
}

// Present always returns ErrSDJWTRequiresJOSE: a VC 1.1 JWT carries no
// disclosures to choose from (#100).
//
// Deprecated: selective disclosure is no longer supported on VC 1.1 JWT. Use
// JOSECredential.Present on a vc+sd-jwt credential.
func (j *JWTCredential) Present(selectedDisclosures []string) (Credential, error) {
	return nil, ErrSDJWTRequiresJOSE
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

// rejectBuildTimeOptions refuses options that only the constructors apply — the
// header's kid (NewJWTCredential, NewJOSECredential) and the SD-JWT options
// (NewJOSECredential) — so a signing call does not drop them silently. Shared by
// JWTCredential and JOSECredential.
func rejectBuildTimeOptions(o *credentialOptions) error {
	if o.verificationMethodKey != "" {
		return fmt.Errorf("WithVerificationMethodKey cannot be applied when signing a JWT: the header's kid was fixed when the token was built — pass the option to NewJWTCredential or NewJOSECredential")
	}
	if o.hasSDOptions() {
		return fmt.Errorf("SD-JWT options cannot be applied when signing: the disclosures were fixed when the token was built — pass them to NewJOSECredential")
	}
	return nil
}
