package vp

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/pilacorp/go-credential-sdk/credential/common/dto"
	"github.com/pilacorp/go-credential-sdk/credential/common/jsonmap"
	"github.com/pilacorp/go-credential-sdk/credential/common/jwt"
)

type JWTPresentation struct {
	signingInput string           // JWT header.payload (base64 encoded)
	payloadData  PresentationData // Parsed payload as PresentationData
	signature    string           // JWT signature (if signed)
}

func NewJWTPresentation(vpc PresentationContents, opts ...PresentationOpt) (Presentation, error) {
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
	header := map[string]interface{}{
		"typ": "JWT",
		"alg": "ES256K",
		"kid": fmt.Sprintf("%s#%s", vpc.Holder, options.verificationMethodKey),
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
		signature:    "",
	}

	// Return JWTPresentation
	return e, e.executeOptions(opts...)
}

func ParseJWTPresentation(rawJWT string, opts ...PresentationOpt) (Presentation, error) {
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
		signature:    signature,
	}

	return e, e.executeOptions(opts...)
}

func (j *JWTPresentation) AddProof(priv string, opts ...PresentationOpt) error {
	signer := jwt.NewJWTSigner(priv)

	// Sign the existing signing input
	signature, err := signer.SignString(j.signingInput)
	if err != nil {
		return fmt.Errorf("failed to sign signing input: %w", err)
	}

	err = j.executeOptions(opts...)
	if err != nil {
		return err
	}

	// Update signature
	j.signature = signature

	return nil
}

func (j *JWTPresentation) GetSigningInput() ([]byte, error) {
	return []byte(j.signingInput), nil
}

func (j *JWTPresentation) AddCustomProof(proof *dto.Proof, opts ...PresentationOpt) error {
	if proof == nil {
		return fmt.Errorf("proof cannot be nil")
	}

	if len(proof.Signature) == 0 {
		return fmt.Errorf("proof signature cannot be empty")
	}

	err := j.executeOptions(opts...)
	if err != nil {
		return err
	}

	j.signature = base64.RawURLEncoding.EncodeToString(proof.Signature)

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

func (j *JWTPresentation) executeOptions(opts ...PresentationOpt) error {
	options := getOptions(opts...)

	if options.isValidateVC {
		if err := verifyCredentials(PresentationData(j.payloadData)); err != nil {
			return fmt.Errorf("failed to verify presentation: %w", err)
		}
	}

	if options.isVerifyProof {
		serialized, err := j.Serialize()
		if err != nil {
			return fmt.Errorf("failed to serialize presentation: %w", err)
		}

		verifier := jwt.NewJWTVerifier(options.didBaseURL)
		err = verifier.VerifyJWT(serialized.(string))
		if err != nil {
			return fmt.Errorf("failed to verify presentation: %w", err)
		}
	}

	return nil
}
