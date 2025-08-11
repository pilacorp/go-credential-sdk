package util

import (
	"fmt"

	"github.com/pilacorp/go-credential-sdk/credential/common/dto"
)

// JSONMap represents a JSON object as a map.
type JSONMap = map[string]interface{}

// JSON field constants for credential serialization.
const (
	jsonFldSubjectID  = "id"
	jsonFldType       = "type"
	jsonFldSchemaID   = "id"
	jsonFldSchemaType = "type"
)

// SerializeTypes converts a slice of type strings to a JSON-LD compatible format.
func SerializeTypes(types []string) interface{} {
	if len(types) == 0 {
		return nil
	}
	if len(types) == 1 {
		return types[0]
	}
	return MapSlice(types, func(t string) interface{} { return t })
}

// MapSlice transforms a slice of type T to a slice of type U using a mapping function.
func MapSlice[T any, U any](slice []T, mapFn func(T) U) []U {
	result := make([]U, 0, len(slice))
	for _, v := range slice {
		result = append(result, mapFn(v))
	}
	return result
}

// serializeContexts validates and converts a slice of JSON-LD context entries.
func SerializeContexts(contexts []interface{}) ([]interface{}, error) {
	validated := make([]interface{}, 0, len(contexts))
	for i, ctx := range contexts {
		if ctx == nil {
			return nil, fmt.Errorf("failed to validate context: context entry at index %d is nil", i)
		}
		switch v := ctx.(type) {
		case string:
			if v == "" {
				return nil, fmt.Errorf("failed to validate context: context string at index %d is empty", i)
			}
			validated = append(validated, v)
		case JSONMap:
			if _, hasContext := v["@context"]; hasContext {
				return nil, fmt.Errorf("failed to validate context: context object at index %d must not contain nested @context", i)
			}
			for key, value := range v {
				if key == "" {
					return nil, fmt.Errorf("failed to validate context: context object at index %d has empty key", i)
				}
				if str, ok := value.(string); ok && str == "" {
					return nil, fmt.Errorf("failed to validate context: context object at index %d has empty string value for key %q", i, key)
				}
			}
			validated = append(validated, v)
		default:
			return nil, fmt.Errorf("failed to validate context: invalid context entry at index %d: must be string or map, got %T", i, v)
		}
	}
	return validated, nil
}

// serializeProofs converts a slice of Proof structs to a JSON-LD compatible format.
func SerializeProofs(proofs []dto.Proof) interface{} {
	if len(proofs) == 0 {
		return nil
	}
	result := make([]JSONMap, len(proofs))
	for i, proof := range proofs {
		proofMap := make(JSONMap)
		if proof.Type != "" {
			proofMap[jsonFldType] = proof.Type
		}
		if proof.Created != "" {
			proofMap["created"] = proof.Created
		}
		if proof.VerificationMethod != "" {
			proofMap["verificationMethod"] = proof.VerificationMethod
		}
		if proof.ProofPurpose != "" {
			proofMap["proofPurpose"] = proof.ProofPurpose
		}
		if proof.ProofValue != "" {
			proofMap["proofValue"] = proof.ProofValue
		}
		if proof.Cryptosuite != "" {
			proofMap["cryptosuite"] = proof.Cryptosuite
		}
		result[i] = proofMap
	}
	if len(result) == 1 {
		return result[0]
	}
	return result
}

// parseProof converts a single proof map into a Proof struct.
func ParseProof(proof map[string]interface{}) (dto.Proof, error) {
	var result dto.Proof
	if t, ok := proof["type"].(string); ok && t != "" {
		result.Type = t
	} else {
		return dto.Proof{}, fmt.Errorf("failed to parse proof: invalid or missing type field")
	}
	if created, ok := proof["created"].(string); ok && created != "" {
		result.Created = created
	} else {
		return dto.Proof{}, fmt.Errorf("failed to parse proof: invalid or missing created field")
	}
	if vm, ok := proof["verificationMethod"].(string); ok && vm != "" {
		result.VerificationMethod = vm
	} else {
		return dto.Proof{}, fmt.Errorf("failed to parse proof: invalid or missing verificationMethod field")
	}
	if pp, ok := proof["proofPurpose"].(string); ok && pp != "" {
		result.ProofPurpose = pp
	} else {
		return dto.Proof{}, fmt.Errorf("failed to parse proof: invalid or missing proofPurpose field")
	}
	if pv, ok := proof["proofValue"].(string); ok {
		result.ProofValue = pv
	}
	if jws, ok := proof["jws"].(string); ok {
		result.JWS = jws
	}
	if disclosures, ok := proof["disclosures"].([]interface{}); ok {
		for _, d := range disclosures {
			if ds, ok := d.(string); ok {
				result.Disclosures = append(result.Disclosures, ds)
			}
		}
	}
	if cs, ok := proof["cryptosuite"].(string); ok {
		result.Cryptosuite = cs
	}
	if ch, ok := proof["challenge"].(string); ok {
		result.Challenge = ch
	}
	if dm, ok := proof["domain"].(string); ok {
		result.Domain = dm
	}
	return result, nil
}
