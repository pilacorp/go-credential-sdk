package vc

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/pilacorp/go-credential-sdk/credential/common/dto"
	"github.com/pilacorp/go-credential-sdk/credential/common/jsonmap"
	"github.com/pilacorp/go-credential-sdk/credential/common/jwt"
)

type JWTHeaders map[string]interface{}

type JWTCredential struct {
	SigningInput string         // JWT header.payload (base64 encoded)
	PayloadData  CredentialData // Parsed payload as CredentialData
	Signature    string         // JWT signature (if signed)
}

func NewJWTCredential(vcc CredentialContents, opts ...CredentialOpt) (Credential, error) {
	options := &credentialOptions{
		isValidateSchema: false,
		didBaseURL:       config.BaseURL,
	}
	for _, opt := range opts {
		opt(options)
	}

	// Convert CredentialContents to CredentialData
	m, err := serializeCredentialContents(&vcc)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize credential contents: %w", err)
	}

	if options.isValidateSchema {
		if err := validateCredential(m); err != nil {
			return nil, fmt.Errorf("failed to validate credential: %w", err)
		}
	}

	payloadData := CredentialData(m)

	// Extract other claims from credentialContents
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

	// Build payload with vc claim and other claims
	payload := map[string]interface{}{
		"vc": payloadData,
	}
	// Add other claims to payload
	for key, value := range otherClaims {
		payload[key] = value
	}

	header := map[string]interface{}{
		"typ": "JWT",
		"alg": "ES256K",
		"kid": fmt.Sprintf("%s#%s", vcc.Issuer, "key-1"),
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

	// Return JWTCredential
	return &JWTCredential{
		SigningInput: signingInput,
		PayloadData:  payloadData,
		Signature:    "",
	}, nil
}

func ParseCredentialJWT(rawJWT string, opts ...CredentialOpt) (Credential, error) {
	if !isJWTCredential(rawJWT) {
		return nil, fmt.Errorf("invalid JWT format")
	}

	options := &credentialOptions{
		isValidateSchema: false,
		didBaseURL:       config.BaseURL,
	}
	for _, opt := range opts {
		opt(options)
	}

	// Parse the JWT credential from rawJWT
	// Remove JSON quotes if present (from json.Marshal of a string)
	rawJWT = strings.Trim(rawJWT, `"`)

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

	// Store the vc claim in payload as payloadData
	vcData, ok := payloadMap["vc"]
	if !ok {
		return nil, fmt.Errorf("vc claim not found in JWT payload")
	}

	vcMap, ok := vcData.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("vc claim is not a valid JSON object")
	}

	if options.isValidateSchema {
		if err := validateCredential(vcMap); err != nil {
			return nil, fmt.Errorf("failed to validate credential: %w", err)
		}
	}

	// Create signing input (header.payload)
	signingInput := headerEncoded + "." + payloadEncoded

	// Return JWTCredential
	return &JWTCredential{
		SigningInput: signingInput,
		PayloadData:  CredentialData(vcMap),
		Signature:    signature,
	}, nil
}

func (j *JWTCredential) AddProof(priv string, opts ...CredentialOpt) error {
	options := &credentialOptions{
		isValidateSchema: false,
		didBaseURL:       config.BaseURL,
	}
	for _, opt := range opts {
		opt(options)
	}

	// Get issuer from PayloadData
	issuer, ok := j.PayloadData["issuer"].(string)
	if !ok {
		return fmt.Errorf("issuer not found in credential")
	}

	signer := jwt.NewJWTSigner(priv, issuer)

	// Sign the existing signing input
	signature, err := signer.SignString(j.SigningInput)
	if err != nil {
		return fmt.Errorf("failed to sign signing input: %w", err)
	}

	// Update signature
	j.Signature = signature
	return nil
}

func (j *JWTCredential) GetSigningInput() ([]byte, error) {
	return []byte(j.SigningInput), nil
}

func (j *JWTCredential) AddCustomProof(proof *dto.Proof) error {
	if proof == nil {
		return fmt.Errorf("proof cannot be nil")
	}

	if len(proof.Signature) == 0 {
		return fmt.Errorf("proof signature cannot be empty")
	}

	// Use the provided signature directly
	j.Signature = base64.RawURLEncoding.EncodeToString(proof.Signature)

	return nil
}

func (j *JWTCredential) Verify(opts ...CredentialOpt) error {
	options := &credentialOptions{
		isValidateSchema: false,
		didBaseURL:       config.BaseURL,
	}
	for _, opt := range opts {
		opt(options)
	}

	// For signed JWT, verify signature
	verifier := jwt.NewJWTVerifier(options.didBaseURL)

	serialized, err := j.Serialize()
	if err != nil {
		return fmt.Errorf("failed to serialize credential: %w", err)
	}

	err = verifier.VerifyJWT(serialized.(string))
	if err != nil {
		return err
	}

	if options.isValidateSchema {
		if err := validateCredential(j.PayloadData); err != nil {
			return fmt.Errorf("failed to validate credential: %w", err)
		}
	}

	return nil
}

func (j *JWTCredential) Serialize() (interface{}, error) {
	if j.Signature != "" {
		// Signed JWT
		return j.SigningInput + "." + j.Signature, nil
	} else {
		// Unsigned JWT
		return j.SigningInput, nil
	}
}

func (j *JWTCredential) GetContents() ([]byte, error) {
	return (*jsonmap.JSONMap)(&j.PayloadData).ToJSON()
}

func (j *JWTCredential) GetType() string {
	return "JWT"
}
