package vc

import (
	"fmt"
	"time"

	"github.com/pilacorp/go-credential-sdk/vc/jsonutil"
	"github.com/pilacorp/go-credential-sdk/vc/util"
)

// JSONMap represents a JSON object as a map.
type JSONMap = map[string]interface{}

// JSON field constants for credential serialization.
const (
	jsonFldSubjectID   = "id"
	jsonFldType        = "type"
	jsonFldTypedIDID   = "id"
	jsonFldTypedIDType = "type"
)

// contextToRaw converts a slice of context strings and custom contexts to a JSON-LD compatible array.
func contextToRaw(context []string, customContext []interface{}) []interface{} {
	result := make([]interface{}, 0, len(context)+len(customContext))
	for _, ctx := range context {
		result = append(result, ctx)
	}
	result = append(result, customContext...)
	return result
}

// serializeTypes converts a slice of type strings to a JSON-LD compatible format (string or array).
func serializeTypes(types []string) interface{} {
	if len(types) == 0 {
		return nil
	}
	if len(types) == 1 {
		return types[0]
	}
	return mapSlice(types, func(t string) interface{} { return t })
}

// SerializeSubject converts a slice of Subject structs to a JSON-LD compatible format.
func SerializeSubject(subjects []Subject) interface{} {
	if len(subjects) == 0 {
		return nil
	}
	if len(subjects) == 1 {
		return subjectToJSON(subjects[0])
	}
	return mapSlice(subjects, subjectToJSON)
}

// subjectToJSON converts a single Subject struct to a JSON object.
func subjectToJSON(subject Subject) JSONMap {
	obj := jsonutil.ShallowCopyObj(subject.CustomFields)
	if subject.ID != "" {
		obj[jsonFldSubjectID] = subject.ID
	}
	return obj
}

// proofsToRaw converts a slice of Proof structs to a JSON-LD compatible format.
func proofsToRaw(proofs []Proof) interface{} {
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
		if proof.JWS != "" {
			proofMap["jws"] = proof.JWS
		}
		if len(proof.Disclosures) > 0 {
			proofMap["disclosures"] = proof.Disclosures
		}
		if proof.Cryptosuite != "" {
			proofMap["cryptosuite"] = proof.Cryptosuite
		}
		if proof.Challenge != "" {
			proofMap["challenge"] = proof.Challenge
		}
		if proof.Domain != "" {
			proofMap["domain"] = proof.Domain
		}
		result[i] = proofMap
	}
	if len(result) == 1 {
		return result[0]
	}
	return result
}

// typedIDsToRaw converts a slice of TypedID structs to a JSON-LD compatible format.
func typedIDsToRaw(typedIDs []TypedID) interface{} {
	if len(typedIDs) == 0 {
		return nil
	}
	if len(typedIDs) == 1 {
		return serializeTypedID(typedIDs[0])
	}
	return mapSlice(typedIDs, serializeTypedID)
}

// serializeTypedID converts a single TypedID struct to a JSON object.
func serializeTypedID(typedID TypedID) JSONMap {
	return JSONMap{
		jsonFldTypedIDID:   typedID.ID,
		jsonFldTypedIDType: typedID.Type,
	}
}

// statusToRaw converts a slice of Status structs to a JSON-LD compatible format.
func statusToRaw(statuses []Status) interface{} {
	if len(statuses) == 0 {
		return nil
	}
	if len(statuses) == 1 {
		return serializeStatus(statuses[0])
	}
	return mapSlice(statuses, serializeStatus)
}

// serializeStatus converts a single Status struct to a JSON object.
func serializeStatus(status Status) JSONMap {
	result := make(JSONMap)
	if status.ID != "" {
		result["id"] = status.ID
	}
	if status.Type != "" {
		result["type"] = status.Type
	}
	if status.StatusPurpose != "" {
		result["statusPurpose"] = status.StatusPurpose
	}
	if status.StatusListIndex != "" {
		result["statusListIndex"] = status.StatusListIndex
	}
	if status.StatusListCredential != "" {
		result["statusListCredential"] = status.StatusListCredential
	}
	return result
}

// serializeTime formats a TimeWrapper to a string.
func serializeTime(t *util.TimeWrapper) interface{} {
	if t == nil {
		return nil
	}
	return t.FormatToString()
}

// validateContext validates a slice of JSON-LD context entries.
func validateContext(contexts []interface{}) ([]interface{}, error) {
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

// parseContext extracts the @context field from a Credential.
func parseContext(c *Credential, contents *CredentialContents) error {
	if context, ok := (*c)["@context"].([]interface{}); ok {
		for _, ctx := range context {
			if ctxStr, ok := ctx.(string); ok {
				contents.Context = append(contents.Context, ctxStr)
			}
		}
	}
	return nil
}

// parseID extracts the ID field from a Credential.
func parseID(c *Credential, contents *CredentialContents) error {
	if id, ok := (*c)["id"].(string); ok {
		contents.ID = id
	}
	return nil
}

// parseTypes extracts the type field from a Credential.
func parseTypes(c *Credential, contents *CredentialContents) error {
	if types, ok := (*c)["type"].([]interface{}); ok {
		for _, t := range types {
			if typeStr, ok := t.(string); ok {
				contents.Types = append(contents.Types, typeStr)
			}
		}
	}
	return nil
}

// parseIssuer extracts the issuer field from a Credential.
func parseIssuer(c *Credential, contents *CredentialContents) error {
	if issuer, ok := (*c)["issuer"].(string); ok {
		contents.Issuer = issuer
	}
	return nil
}

// parseDates extracts validFrom and validUntil fields from a Credential.
func parseDates(c *Credential, contents *CredentialContents) error {
	if validFrom, ok := (*c)["validFrom"].(string); ok {
		t, err := time.Parse(time.RFC3339, validFrom)
		if err != nil {
			return fmt.Errorf("failed to parse validFrom: %w", err)
		}
		contents.ValidFrom = t
	}
	if validUntil, ok := (*c)["validUntil"].(string); ok {
		t, err := time.Parse(time.RFC3339, validUntil)
		if err != nil {
			return fmt.Errorf("failed to parse validUntil: %w", err)
		}
		contents.ValidUntil = t
	}
	return nil
}

// parseSubject extracts the credentialSubject field from a Credential.
func parseSubject(c *Credential, contents *CredentialContents) error {
	if subject, ok := (*c)["credentialSubject"].(map[string]interface{}); ok {
		s := Subject{
			CustomFields: make(map[string]interface{}),
		}
		if id, ok := subject["id"].(string); ok {
			s.ID = id
		}
		for k, v := range subject {
			if k != "id" {
				s.CustomFields[k] = v
			}
		}
		contents.Subject = append(contents.Subject, s)
	}
	return nil
}

// parseSchema extracts the credentialSchema field from a Credential.
func parseSchema(c *Credential, contents *CredentialContents) error {
	if schema, ok := (*c)["credentialSchema"].(map[string]interface{}); ok {
		schemaID, err := parseTypedID(schema)
		if err != nil {
			return fmt.Errorf("failed to parse schema: %w", err)
		}
		contents.Schemas = append(contents.Schemas, schemaID)
	}
	return nil
}

// parseStatus extracts the credentialStatus field from a Credential.
func parseStatus(c *Credential, contents *CredentialContents) error {
	if status, ok := (*c)["credentialStatus"].(map[string]interface{}); ok {
		s := Status{}
		if id, ok := status["id"].(string); ok {
			s.ID = id
		}
		if t, ok := status["type"].(string); ok {
			s.Type = t
		}
		if purpose, ok := status["statusPurpose"].(string); ok {
			s.StatusPurpose = purpose
		}
		if index, ok := status["statusListIndex"].(string); ok {
			s.StatusListIndex = index
		}
		if cred, ok := status["statusListCredential"].(string); ok {
			s.StatusListCredential = cred
		}
		contents.CredentialStatus = append(contents.CredentialStatus, s)
	} else if statuses, ok := (*c)["credentialStatus"].([]interface{}); ok {
		for _, status := range statuses {
			if statusMap, ok := status.(map[string]interface{}); ok {
				s := Status{}
				if id, ok := statusMap["id"].(string); ok {
					s.ID = id
				}
				if t, ok := statusMap["type"].(string); ok {
					s.Type = t
				}
				if purpose, ok := statusMap["statusPurpose"].(string); ok {
					s.StatusPurpose = purpose
				}
				if index, ok := statusMap["statusListIndex"].(string); ok {
					s.StatusListIndex = index
				}
				if cred, ok := statusMap["statusListCredential"].(string); ok {
					s.StatusListCredential = cred
				}
				contents.CredentialStatus = append(contents.CredentialStatus, s)
			}
		}
	}
	return nil
}

// parseTypedID parses a TypedID from a value.
func parseTypedID(value interface{}) (TypedID, error) {
	var tid TypedID
	switch v := value.(type) {
	case string:
		tid.ID = v
	case map[string]interface{}:
		if id, ok := v["id"].(string); ok {
			tid.ID = id
		}
		if t, ok := v["type"].(string); ok {
			tid.Type = t
		}
	default:
		return tid, fmt.Errorf("failed to parse typed ID: invalid format %T", value)
	}
	return tid, nil
}

// parseProof converts an interface{} (JSON object) to a Proof struct.
func parseRawToProof(proof interface{}) (Proof, error) {
	var result Proof

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
	if disclosures, ok := proofMap["disclosures"].([]interface{}); ok {
		for _, d := range disclosures {
			if ds, ok := d.(string); ok {
				result.Disclosures = append(result.Disclosures, ds)
			}
		}
	}
	if cs, ok := proofMap["cryptosuite"].(string); ok {
		result.Cryptosuite = cs
	}
	if ch, ok := proofMap["challenge"].(string); ok {
		result.Challenge = ch
	}
	if dm, ok := proofMap["domain"].(string); ok {
		result.Domain = dm
	}

	return result, nil
}
