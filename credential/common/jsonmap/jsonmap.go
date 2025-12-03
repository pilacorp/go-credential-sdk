package jsonmap

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/pilacorp/go-credential-sdk/credential/common/crypto"
	"github.com/pilacorp/go-credential-sdk/credential/common/dto"
	"github.com/pilacorp/go-credential-sdk/credential/common/processor"
	"github.com/pilacorp/go-credential-sdk/credential/common/util"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
)

// JSONMap represents a JSON object as a map.
type JSONMap map[string]interface{}

const (
	JwtProof2020                string = "JwtProof2020"
	EcdsaSecp256k1Signature2019 string = "EcdsaSecp256k1Signature2019"
	DataIntegrityProof          string = "DataIntegrityProof"
	ECDSARDFC2019               string = "ecdsa-rdfc-2019"
	ECDSASECPKEY                string = "EcdsaSecp256k1VerificationKey2019"
)

// ToJSON serializes the JSONMap to JSON.
func (m *JSONMap) ToJSON() ([]byte, error) {
	if m == nil {
		return nil, fmt.Errorf("JSONMap is nil")
	}

	data, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JSONMap: %w", err)
	}

	var temp JSONMap
	if err := json.Unmarshal(data, &temp); err != nil {
		return nil, fmt.Errorf("failed to validate serialization: %w", err)
	}
	return data, nil
}

func (m *JSONMap) ToMap() (map[string]interface{}, error) {
	// Marshal the JSONMap to bytes
	bytes, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JSONMap: %w", err)
	}

	// Unmarshal the bytes to a map
	var data map[string]interface{}
	if err := json.Unmarshal(bytes, &data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSONMap: %w", err)
	}

	return data, nil
}

// Canonicalize canonicalizes the JSONMap for signing or verification, excluding the proof field.
func (m *JSONMap) Canonicalize() ([]byte, error) {
	mCopy := make(JSONMap)
	for k, v := range *m {
		if k != "proof" {
			mCopy[k] = v
		}
	}

	encoded, err := json.Marshal(mCopy)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JSONMap copy: %w", err)
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(encoded, &doc); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSONMap copy: %w", err)
	}

	canonicalDoc, err := processor.CanonicalizeDocument(doc)
	if err != nil {
		return nil, fmt.Errorf("failed to canonicalize document: %w", err)
	}

	return processor.ComputeDigest(canonicalDoc)
}

// AddECDSAProof adds an ECDSA proof to the JSONMap.
func (m *JSONMap) AddECDSAProof(priv, verificationMethod, proofPurpose, didBaseURL string) error {
	if m == nil {
		return fmt.Errorf("JSONMap is nil")
	}
	if verificationMethod == "" {
		return fmt.Errorf("verification method is required")
	}
	if proofPurpose == "" {
		return fmt.Errorf("proof purpose is required")
	}

	resolver := verificationmethod.NewResolver(didBaseURL)
	isValid, err := resolver.CheckVerificationMethod(priv, verificationMethod)
	if err != nil {
		return fmt.Errorf("failed to verify Private key and verification method: %w", err)
	}
	if !isValid {
		return fmt.Errorf("private key and verification method do not match")
	}

	proof := &dto.Proof{
		Type:               DataIntegrityProof,
		Created:            time.Now().UTC().Format(time.RFC3339),
		VerificationMethod: verificationMethod,
		ProofPurpose:       proofPurpose,
		Cryptosuite:        ECDSARDFC2019,
	}

	signData, err := m.Canonicalize()
	if err != nil {
		return fmt.Errorf("failed to canonicalize JSONMap: %w", err)
	}

	signature, err := crypto.ECDSASign(signData, priv)
	if err != nil {
		return fmt.Errorf("failed to sign ECDSA proof: %w", err)
	}
	proof.ProofValue = hex.EncodeToString(signature)
	(*m)["proof"] = util.SerializeProofs([]dto.Proof{*proof})

	return nil
}

// AddCustomProof adds custom proof to the JSONMap.
func (m *JSONMap) AddCustomProof(proof *dto.Proof) error {
	if m == nil {
		return fmt.Errorf("JSONMap is nil")
	}
	if proof == nil {
		return fmt.Errorf("proof is nil")
	}
	(*m)["proof"] = util.SerializeProofs([]dto.Proof{*proof})

	return nil
}

// parseRawToProof converts a JSON object to a Proof struct.
func ParseRawToProof(proof interface{}) (dto.Proof, error) {
	var result dto.Proof
	proofMap, ok := proof.(map[string]interface{})
	if !ok {
		return result, fmt.Errorf("invalid proof format: expected map[string]interface{}, got %T", proof)
	}

	if t, ok := proofMap["type"].(string); ok {
		result.Type = t
	}
	if created, ok := proofMap["created"].(string); ok {
		result.Created = created
	}
	if purpose, ok := proofMap["proofPurpose"].(string); ok {
		result.ProofPurpose = purpose
	}
	if vm, ok := proofMap["verificationMethod"].(string); ok {
		result.VerificationMethod = vm
	}
	if pv, ok := proofMap["proofValue"].(string); ok {
		result.ProofValue = pv
	}
	if jws, ok := proofMap["jws"].(string); ok {
		result.JWS = jws
	}
	if pv, ok := proofMap["cryptosuite"].(string); ok {
		result.Cryptosuite = pv
	}

	return result, nil
}

// VerifyProof verifies an ECDSA-signed JSONMap.
func (m *JSONMap) VerifyProof(didBaseURL string) (bool, error) {
	if m == nil {
		return false, fmt.Errorf("JSONMap is nil")
	}

	proofs, ok := (*m)["proof"].([]interface{})
	if !ok {
		if proof, exists := (*m)["proof"]; exists {
			proofs = []interface{}{proof}
		} else {
			return false, fmt.Errorf("JSONMap has no proof")
		}
	}
	proof, err := ParseRawToProof(proofs[0])
	if err != nil {
		return false, fmt.Errorf("failed to parse proof: %w", err)
	}

	if proof.Type == JwtProof2020 {
		issuerDID, ok := (*m)["issuer"].(string)
		if !ok {
			return false, fmt.Errorf("issuer is missing or invalid in the request")
		}

		resolver := verificationmethod.NewResolver(didBaseURL)
		publicKey, err := resolver.GetDefaultPublicKey(issuerDID)
		if err != nil {
			return false, fmt.Errorf("failed to resolve public key: %w", err)
		}

		return crypto.VerifyJwtProof((*map[string]interface{})(m), publicKey)
	} else if proof.Type == EcdsaSecp256k1Signature2019 || proof.Type == ECDSASECPKEY {
		return m.verifyEcdsaProofLegacy(didBaseURL, &proof)
	} else if proof.Type == DataIntegrityProof && proof.Cryptosuite == ECDSARDFC2019 {
		resolver := verificationmethod.NewResolver(didBaseURL)
		publicKey, err := resolver.GetPublicKey(proof.VerificationMethod)
		if err != nil {
			return false, fmt.Errorf("failed to resolve public key: %w", err)
		}

		return m.verifyECDSA(publicKey, &proof)
	} else {

		return false, fmt.Errorf("unsupported proof type: %s", proof.Type)
	}
}

// VerifyECDSA verifies an ECDSA-signed JSONMap.
func (m *JSONMap) verifyECDSA(publicKey string, proof *dto.Proof) (bool, error) {
	doc, err := m.Canonicalize()
	if err != nil {
		return false, fmt.Errorf("failed to canonicalize JSONMap: %w", err)
	}

	return crypto.ECDSAVerifySignature(publicKey, proof.ProofValue, doc)
}

// verifyEcdsaProofLegacy verifies an ECDSA-signed JSONMap.
// This function support legacy VC for compatibility
// It handles both proofValue (JSON-LD signature) and jws (JWT signature) formats
func (m *JSONMap) verifyEcdsaProofLegacy(didBaseURL string, proof *dto.Proof) (bool, error) {
	proofMap, ok := (*m)["proof"].(map[string]interface{})
	if !ok {
		return false, fmt.Errorf("proof is missing or invalid in the request")
	}

	// Check if proof has jws field (JWT-based signature)
	if jws, ok := proofMap["jws"].(string); ok && jws != "" {
		return m.verifyJWS(jws, didBaseURL, proof)
	}

	// Otherwise, check for proofValue (JSON-LD signature)
	proofValue, ok := proofMap["proofValue"].(string)
	if !ok || proofValue == "" {
		return false, fmt.Errorf("proof value is missing or invalid in the request")
	}

	verificationMethod, ok := proofMap["verificationMethod"].(string)
	if !ok || verificationMethod == "" {
		return false, fmt.Errorf("proof verificationMethod is missing or invalid in the request")
	}

	signatureBytes, err := hex.DecodeString(proofValue)
	if err != nil {
		return false, fmt.Errorf("failed to decode proof value to bytes: %w", err)
	}

	reqCopy := make(map[string]interface{})

	for k, v := range *m {
		if k != "proof" {
			reqCopy[k] = v
		}
	}

	message, err := json.Marshal(reqCopy)
	if err != nil {
		return false, fmt.Errorf("failed to marshal request to JSON: %w", err)
	}

	// Resolve public key from verification method
	resolver := verificationmethod.NewResolver(didBaseURL)
	publicKeyHex, err := resolver.GetPublicKey(verificationMethod)
	if err != nil {
		return false, fmt.Errorf("failed to resolve public key: %w", err)
	}

	// Ensure public key has 0x prefix for KeyToBytes
	if !strings.HasPrefix(publicKeyHex, "0x") {
		publicKeyHex = "0x" + publicKeyHex
	}

	pubBytes, err := crypto.KeyToBytes(publicKeyHex)
	if err != nil {
		return false, fmt.Errorf("failed to convert public key to bytes: %w", err)
	}

	verified := crypto.VerifyJSONSignature(pubBytes, message, signatureBytes)

	return verified, nil
}

// verifyJWS verifies a JWS (JSON Web Signature) token in EcdsaSecp256k1Signature2019 proof
func (m *JSONMap) verifyJWS(jwsToken string, didBaseURL string, proof *dto.Proof) (bool, error) {
	if proof.VerificationMethod == "" {
		return false, fmt.Errorf("verificationMethod is required for JWS verification")
	}

	// Extract signature and message from JWS token
	signature, message, err := getSignatureAndMessageFromJWS(jwsToken)
	if err != nil {
		return false, fmt.Errorf("failed to extract signature and message from JWS: %w", err)
	}

	// Resolve public key from verification method
	resolver := verificationmethod.NewResolver(didBaseURL)
	publicKeyHex, err := resolver.GetDefaultPublicKey(proof.VerificationMethod)
	if err != nil {
		return false, fmt.Errorf("failed to resolve public key: %w", err)
	}

	// Ensure public key has 0x prefix for KeyToBytes
	if !strings.HasPrefix(publicKeyHex, "0x") {
		publicKeyHex = "0x" + publicKeyHex
	}

	pubBytes, err := crypto.KeyToBytes(publicKeyHex)
	if err != nil {
		return false, fmt.Errorf("failed to convert public key to bytes: %w", err)
	}

	verified := crypto.VerifySignature(pubBytes, message, signature)

	return verified, nil
}

// getSignatureAndMessageFromJWS extracts signature and message from a JWS token
func getSignatureAndMessageFromJWS(jwsToken string) ([]byte, []byte, error) {
	parts := strings.Split(jwsToken, ".")
	if len(parts) != 3 {
		return nil, nil, fmt.Errorf("invalid JWS format: expected 3 parts, got %d", len(parts))
	}

	headerB64, payloadB64, signatureB64 := parts[0], parts[1], parts[2]

	signature, err := base64.RawURLEncoding.DecodeString(signatureB64)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode signature: %w", err)
	}

	message := []byte(headerB64 + "." + payloadB64)

	return signature, message, nil
}
