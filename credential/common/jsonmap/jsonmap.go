package jsonmap

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/pilacorp/go-credential-sdk/credential/common/crypto"
	"github.com/pilacorp/go-credential-sdk/credential/common/dto"
	"github.com/pilacorp/go-credential-sdk/credential/common/processor"
	"github.com/pilacorp/go-credential-sdk/credential/common/util"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
)

// JSONMap represents a JSON object as a map.
type JSONMap map[string]interface{}

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
		Type:               "DataIntegrityProof",
		Created:            time.Now().UTC().Format(time.RFC3339),
		VerificationMethod: verificationMethod,
		ProofPurpose:       proofPurpose,
		Cryptosuite:        "ecdsa-rdfc-2019",
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

// VerifyECDSA verifies an ECDSA-signed JSONMap.
func (m *JSONMap) VerifyECDSA(didBaseURL string) (bool, error) {
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

	doc, err := m.Canonicalize()
	if err != nil {
		return false, fmt.Errorf("failed to canonicalize JSONMap: %w", err)
	}

	proof, err := ParseRawToProof(proofs[0])
	if err != nil {
		return false, fmt.Errorf("failed to parse proof: %w", err)
	}

	resolver := verificationmethod.NewResolver(didBaseURL)
	publicKey, err := resolver.GetPublicKey(proof.VerificationMethod)
	if err != nil {
		return false, fmt.Errorf("failed to resolve public key: %w", err)
	}

	return crypto.ECDSAVerifySignature(publicKey, proof.ProofValue, doc)
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
	return result, nil
}
