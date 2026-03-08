package vc

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/pilacorp/go-credential-sdk/credential/common/dto"
	"github.com/pilacorp/go-credential-sdk/credential/common/jsonmap"
	"github.com/pilacorp/go-credential-sdk/credential/common/jwt"
	"github.com/pilacorp/go-credential-sdk/credential/common/sdjwt"
	"golang.org/x/sync/errgroup"
)

type JWTHeaders map[string]interface{}

type JWTCredential struct {
	signingInput string         // JWT header.payload (base64 encoded)
	payloadData  CredentialData // Parsed payload as CredentialData
	signature    string         // JWT signature (if signed)
	disclosures  []string       // Optional SD-JWT disclosures (when issuing/holding SD-JWT)
}

func NewJWTCredential(vcc CredentialContents, opts ...CredentialOpt) (Credential, error) {
	// Convert CredentialContents to a generic map representation
	m, err := serializeCredentialContents(&vcc)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize credential contents: %w", err)
	}

	// Normalize any nested CredentialData/JSONMap into plain map[string]interface{}
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
	disclosures := result.Disclosures

	disclosures = append(disclosures, options.sdDisclosures...)

	payloadData := CredentialData(vcMap)

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
		"kid": fmt.Sprintf("%s#%s", vcc.Issuer, options.verificationMethodKey),
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

	e := &JWTCredential{
		signingInput: signingInput,
		payloadData:  payloadData,
		signature:    "",
		disclosures:  disclosures,
	}

	// Return JWTCredential
	return e, e.executeOptions(opts...)
}

func ParseJWTCredential(rawJWT string, opts ...CredentialOpt) (Credential, error) {
	// prevent " from marshalling to json
	rawJWT = strings.TrimSpace(strings.Trim(rawJWT, "\""))

	var (
		issuerJWT   string
		disclosures []string
	)

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

	// Split issuer-signed JWT into parts
	parts := strings.Split(issuerJWT, ".")

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

	// If this was an SD-JWT, reconstruct processed payload using disclosures.
	// Allow unreferenced disclosures since holder may present only a subset of disclosures.
	if len(disclosures) > 0 {
		config := &sdjwt.ValidationConfig{
			AllowUnreferencedDisclosures: true,
		}
		processed, err := sdjwt.Reconstruct(vcMap, disclosures, config)
		if err != nil {
			return nil, fmt.Errorf("failed to reconstruct SD-JWT payload: %w", err)
		}
		vcMap = processed
	}

	// Create signing input (header.payload)
	signingInput := headerEncoded + "." + payloadEncoded

	e := &JWTCredential{
		signingInput: signingInput,
		payloadData:  CredentialData(vcMap),
		signature:    signature,
		disclosures:  disclosures,
	}

	return e, e.executeOptions(opts...)
}

func (j *JWTCredential) AddProof(priv string, opts ...CredentialOpt) error {
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

func (j *JWTCredential) GetSigningInput() ([]byte, error) {
	return []byte(j.signingInput), nil
}

func (j *JWTCredential) AddCustomProof(proof *dto.Proof, opts ...CredentialOpt) error {
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

	// Use the provided signature directly
	j.signature = base64.RawURLEncoding.EncodeToString(proof.Signature)

	return nil
}

func (j *JWTCredential) Verify(opts ...CredentialOpt) error {
	opts = append(opts, WithVerifyProof())

	return j.executeOptions(opts...)
}

func (j *JWTCredential) Serialize() (interface{}, error) {
	base := j.signingInput
	// For SD-JWT, spec expects an issuer-signed JWT (JWS) as the first component.
	// To keep the compact form consistent, we always add the third segment (even
	// when the signature is empty) whenever disclosures are present.
	if j.signature != "" || len(j.disclosures) > 0 {
		base = base + "." + j.signature
	}

	// No disclosures => plain JWT
	if len(j.disclosures) == 0 {
		return base, nil
	}

	// With disclosures => SD-JWT: <JWT>~D1~...~Dn~
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

func (j *JWTCredential) GetContents() ([]byte, error) {
	return (*jsonmap.JSONMap)(&j.payloadData).ToJSON()
}

func (j *JWTCredential) GetType() string {
	return "JWT"
}

func (j *JWTCredential) AddSelectiveDisclosures(selectivePaths []string) (Credential, error) {
	if len(selectivePaths) == 0 {
		return nil, fmt.Errorf("selective paths cannot be empty")
	}

	// Decode the payload from signingInput to get the vc claim with _sd metadata
	parts := strings.Split(j.signingInput, ".")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid signing input format")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("failed to unmarshal payload: %w", err)
	}

	// Get the vc claim
	vcData, ok := payload["vc"]
	if !ok {
		return nil, fmt.Errorf("vc claim not found in payload")
	}

	vcMap, ok := vcData.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("vc claim is not a valid JSON object")
	}

	var allDisclosures []string
	var processedVC map[string]interface{}

	if len(j.disclosures) > 0 {
		// Existing SD-JWT: extract existing field names from disclosures
		existingFields, err := extractExistingFieldNames(j.disclosures)
		if err != nil {
			return nil, fmt.Errorf("failed to extract existing fields: %w", err)
		}

		// Collect ALL paths: existing + new
		// Existing fields are direct field names like "firstname", need to add credentialSubject. prefix
		var allPaths []string
		for p := range existingFields {
			allPaths = append(allPaths, "credentialSubject."+p)
		}
		for _, p := range selectivePaths {
			fieldName := extractFieldName(p)
			if !existingFields[fieldName] {
				allPaths = append(allPaths, p)
			}
		}

		if len(allPaths) == len(existingFields) {
			// All new paths already disclosed
			return j, nil
		}

		// Reconstruct to get original data (without _sd)
		config := &sdjwt.ValidationConfig{
			AllowUnreferencedDisclosures: true,
		}
		reconstructed, err := sdjwt.Reconstruct(vcMap, j.disclosures, config)
		if err != nil {
			return nil, fmt.Errorf("failed to reconstruct SD-JWT payload: %w", err)
		}

		// Build disclosures for ALL paths
		result, err := sdjwt.BuildDisclosures(sdjwt.BuildDisclosuresInput{
			VC:             reconstructed,
			SelectivePaths: allPaths,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to build disclosures: %w", err)
		}

		processedVC = result.ProcessedVC
		allDisclosures = result.Disclosures
	} else {
		// No existing disclosures - build disclosures for all new paths
		result, err := sdjwt.BuildDisclosures(sdjwt.BuildDisclosuresInput{
			VC:             vcMap,
			SelectivePaths: selectivePaths,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to build disclosures: %w", err)
		}
		processedVC = result.ProcessedVC
		allDisclosures = result.Disclosures
	}

	// Update the payload with the processed VC (contains _sd digests)
	payload["vc"] = processedVC

	// Re-encode the payload
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal updated payload: %w", err)
	}
	payloadEncoded := base64.RawURLEncoding.EncodeToString(payloadJSON)

	// Create new signing input
	newSigningInput := parts[0] + "." + payloadEncoded

	newCred := &JWTCredential{
		signingInput: newSigningInput,
		payloadData:  CredentialData(processedVC),
		signature:    "", // Signature will be added by AddProof later
		disclosures:  allDisclosures,
	}

	return newCred, nil
}

func (j *JWTCredential) executeOptions(opts ...CredentialOpt) error {
	options := getOptions(opts...)

	g := &errgroup.Group{}

	if options.isValidateSchema {
		g.Go(func() error {
			if err := validateCredential(j.payloadData); err != nil {
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
			serialized, err := j.Serialize()
			if err != nil {
				return fmt.Errorf("serialize credential: %w", err)
			}

			verifier := jwt.NewJWTVerifier(options.didBaseURL)
			if err := verifier.VerifyJWT(serialized.(string)); err != nil {
				return fmt.Errorf("verify proof: %w", err)
			}

			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return fmt.Errorf("credential verification failed: %w", err)
	}

	// checkExpiration always runs sequentially after parallel validations
	if options.isCheckExpiration {
		if err := checkExpiration(j.payloadData); err != nil {
			return fmt.Errorf("failed to check expiration: %w", err)
		}
	}

	return nil
}

// extractExistingFieldNames extracts field names from existing disclosures
func extractExistingFieldNames(disclosures []string) (map[string]bool, error) {
	existingFields := make(map[string]bool)
	for _, d := range disclosures {
		if d == "" {
			continue
		}
		decoded, err := base64.RawURLEncoding.DecodeString(d)
		if err != nil {
			continue
		}
		var arr []interface{}
		if err := json.Unmarshal(decoded, &arr); err != nil {
			continue
		}
		// Object field disclosure: [salt, fieldName, value]
		// Array element disclosure: [salt, value]
		if len(arr) >= 2 {
			if fieldName, ok := arr[1].(string); ok {
				existingFields[fieldName] = true
			}
		}
	}
	return existingFields, nil
}

// extractFieldName extracts the field name from a path like "credentialSubject.firstname" or "credentialSubject.emails[0]"
func extractFieldName(path string) string {
	// Get the last part of the path
	parts := strings.Split(path, ".")
	fieldName := parts[len(parts)-1]
	// Remove array index if present
	if idx := strings.Index(fieldName, "["); idx != -1 {
		fieldName = fieldName[:idx]
	}
	return fieldName
}
