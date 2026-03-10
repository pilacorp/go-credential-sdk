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
	disclosures := result.Disclosures
	disclosures = append(disclosures, options.sdDisclosures...)

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

	header := map[string]interface{}{
		"typ": "JWT",
		"alg": "ES256K",
		"kid": fmt.Sprintf("%s#%s", vcc.Issuer, options.verificationMethodKey),
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
		signature:    "",
		disclosures:  disclosures,
	}

	return e, e.executeOptions(opts...)
}

func ParseJWTCredential(rawJWT string, opts ...CredentialOpt) (Credential, error) {
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

	if len(disclosures) > 0 {
		processed, err := sdjwt.Reconstruct(vcMap, disclosures, true)
		if err != nil {
			return nil, fmt.Errorf("failed to reconstruct SD-JWT payload: %w", err)
		}
		vcMap = processed
	}

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
	signature, err := signer.SignString(j.signingInput)
	if err != nil {
		return fmt.Errorf("failed to sign signing input: %w", err)
	}

	err = j.executeOptions(opts...)
	if err != nil {
		return err
	}

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

	j.signature = base64.RawURLEncoding.EncodeToString(proof.Signature)
	return nil
}

func (j *JWTCredential) Verify(opts ...CredentialOpt) error {
	opts = append(opts, WithVerifyProof())
	return j.executeOptions(opts...)
}

func (j *JWTCredential) Serialize() (interface{}, error) {
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

func (j *JWTCredential) GetContents() ([]byte, error) {
	return (*jsonmap.JSONMap)(&j.payloadData).ToJSON()
}

func (j *JWTCredential) GetType() string {
	return "JWT"
}

func (j *JWTCredential) ExtractField(path string) interface{} {
	if j.payloadData == nil {
		return nil
	}
	return extractFieldFromMap(j.payloadData, path)
}

func (j *JWTCredential) AddSelectiveDisclosures(selectivePaths []string) (Credential, error) {
	if len(selectivePaths) == 0 {
		return nil, fmt.Errorf("selective paths cannot be empty")
	}

	payload, header, err := j.extractPayload()
	if err != nil {
		return nil, err
	}

	vcMap, ok := payload["vc"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("vc claim not found in payload")
	}

	allPaths := selectivePaths
	if len(j.disclosures) > 0 {
		// Reconstruct to get original data with all fields
		original, err := sdjwt.Reconstruct(vcMap, j.disclosures, true)
		if err != nil {
			return nil, fmt.Errorf("failed to reconstruct: %w", err)
		}
		// Get existing paths from comparison
		existing := findDisclosedPaths(original, vcMap)
		allPaths = append(existing, selectivePaths...)
		vcMap = original // Use original data for building disclosures
	}

	result, err := sdjwt.BuildDisclosures(sdjwt.BuildDisclosuresInput{
		VC:             vcMap,
		SelectivePaths: unique(allPaths),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to build disclosures: %w", err)
	}
	return j.buildCredential(payload, header, result.ProcessedVC, result.Disclosures)
}

func (j *JWTCredential) extractPayload() (map[string]interface{}, string, error) {
	parts := strings.Split(j.signingInput, ".")
	if len(parts) != 2 {
		return nil, "", fmt.Errorf("invalid signing input format")
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, "", fmt.Errorf("failed to decode payload: %w", err)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, "", fmt.Errorf("failed to unmarshal payload: %w", err)
	}
	return payload, parts[0], nil
}

func (j *JWTCredential) buildCredential(payload map[string]interface{}, header string, vc map[string]interface{}, disc []string) (*JWTCredential, error) {
	// Replace vc claim while preserving all other payload claims (iss, sub, exp, iat, nbf, jti, etc.)
	payload["vc"] = vc
	
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(payloadJSON)
	return &JWTCredential{
		signingInput: header + "." + encoded,
		payloadData:  CredentialData(vc),
		disclosures:  disc,
	}, nil
}

func unique(paths []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, p := range paths {
		if !seen[p] {
			seen[p] = true
			result = append(result, p)
		}
	}
	return result
}

func findDisclosedPaths(original, processed map[string]interface{}) []string {
	var paths []string
	for key := range original {
		if key == "_sd" || key == "_sd_alg" {
			continue
		}
		origVal := original[key]
		procVal, exists := processed[key]
		if !exists {
			continue
		}
		origMap, origOk := origVal.(map[string]interface{})
		procMap, procOk := procVal.(map[string]interface{})
		if origOk && procOk {
			nestedPaths := compareObjects(origMap, procMap, key)
			paths = append(paths, nestedPaths...)
		}
	}
	return paths
}

func compareObjects(orig, proc map[string]interface{}, prefix string) []string {
	var paths []string
	for key, origVal := range orig {
		if key == "_sd" || key == "_sd_alg" {
			continue
		}
		procVal, exists := proc[key]
		if !exists {
			paths = append(paths, prefix+"."+key)
			continue
		}
		if nestedOrig, ok := origVal.(map[string]interface{}); ok {
			if nestedProc, ok := procVal.(map[string]interface{}); ok {
				nestedPaths := compareObjects(nestedOrig, nestedProc, prefix+"."+key)
				paths = append(paths, nestedPaths...)
			}
		}
		if arrOrig, ok := origVal.([]interface{}); ok {
			if arrProc, ok := procVal.([]interface{}); ok {
				arrPaths := compareArrays(arrOrig, arrProc, prefix+"."+key)
				paths = append(paths, arrPaths...)
			}
		}
	}
	return paths
}

func compareArrays(orig, proc []interface{}, prefix string) []string {
	var paths []string
	// Use proc length to handle cases where proc is longer (due to decoy insertion)
	// or shorter (due to selective disclosure removing elements)
	maxLen := len(proc)
	if len(orig) > maxLen {
		maxLen = len(orig)
	}

	for i := 0; i < maxLen; i++ {
		if i >= len(proc) {
			// proc is shorter - remaining orig elements were selectively disclosed
			paths = append(paths, fmt.Sprintf("%s[%d]", prefix, i))
			continue
		}
		if i >= len(orig) {
			// proc is longer - extra elements in proc are disclosed (decoys or revealed values)
			paths = append(paths, fmt.Sprintf("%s[%d]", prefix, i))
			continue
		}
		origElem := orig[i]
		procElem := proc[i]
		if procMap, ok := procElem.(map[string]interface{}); ok {
			if _, hasDots := procMap["..."]; hasDots {
				paths = append(paths, fmt.Sprintf("%s[%d]", prefix, i))
				continue
			}
		}
		if nestedOrig, ok := origElem.(map[string]interface{}); ok {
			if nestedProc, ok := procElem.(map[string]interface{}); ok {
				nestedPaths := compareObjects(nestedOrig, nestedProc, fmt.Sprintf("%s[%d]", prefix, i))
				paths = append(paths, nestedPaths...)
			}
		}
	}
	return paths
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
			serialized, err := j.Serialize()
			if err != nil {
				return fmt.Errorf("serialize credential: %w", err)
			}

			verifier := jwt.NewJWTVerifierWithResolver(options.resolver)
			if err := verifier.VerifyJWT(serialized.(string)); err != nil {
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
