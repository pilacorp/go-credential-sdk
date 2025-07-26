package vc

import (
	"fmt"
	"time"
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

// serializeCredentialContents serializes CredentialContents into a Credential.
func serializeCredentialContents(vcc *CredentialContents) (Credential, error) {
	if vcc == nil {
		return nil, fmt.Errorf("failed to serialize credential contents: contents is nil")
	}
	vcJSON := make(Credential)
	if len(vcc.Context) > 0 {
		validatedContext, err := serializeContexts(vcc.Context)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize credential contents: invalid @context: %w", err)
		}
		vcJSON["@context"] = validatedContext
	}
	if vcc.ID != "" {
		vcJSON["id"] = vcc.ID
	}
	if len(vcc.Types) > 0 {
		vcJSON["type"] = serializeTypes(vcc.Types)
	}
	if len(vcc.Subject) > 0 {
		vcJSON["credentialSubject"] = serializeSubjects(vcc.Subject)
	}
	if len(vcc.Proofs) > 0 {
		vcJSON["proof"] = serializeProofs(vcc.Proofs)
	}
	if vcc.Issuer != "" {
		vcJSON["issuer"] = vcc.Issuer
	}
	if len(vcc.Schemas) > 0 {
		vcJSON["credentialSchema"] = serializeSchemas(vcc.Schemas)
	}
	if len(vcc.CredentialStatus) > 0 {
		vcJSON["credentialStatus"] = serializeStatuses(vcc.CredentialStatus)
	}
	if !vcc.ValidFrom.IsZero() {
		vcJSON["validFrom"] = vcc.ValidFrom.Format(time.RFC3339)
	}
	if !vcc.ValidUntil.IsZero() {
		vcJSON["validUntil"] = vcc.ValidUntil.Format(time.RFC3339)
	}
	return vcJSON, nil
}

// serializeTypes converts a slice of type strings to a JSON-LD compatible format.
func serializeTypes(types []string) interface{} {
	if len(types) == 0 {
		return nil
	}
	if len(types) == 1 {
		return types[0]
	}
	return mapSlice(types, func(t string) interface{} { return t })
}

// serializeSubjects converts a slice of Subject structs to a JSON-LD compatible format.
func serializeSubjects(subjects []Subject) interface{} {
	if len(subjects) == 0 {
		return nil
	}
	if len(subjects) == 1 {
		return serializeSubject(subjects[0])
	}
	return mapSlice(subjects, serializeSubject)
}

// serializeSubject converts a single Subject struct to a JSON object.
func serializeSubject(subject Subject) JSONMap {
	obj := make(JSONMap)
	if subject.ID != "" {
		obj[jsonFldSubjectID] = subject.ID
	}
	for k, v := range subject.CustomFields {
		obj[k] = v
	}
	return obj
}

// serializeProofs converts a slice of Proof structs to a JSON-LD compatible format.
func serializeProofs(proofs []Proof) interface{} {
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
		result[i] = proofMap
	}
	if len(result) == 1 {
		return result[0]
	}
	return result
}

// serializeSchemas converts a slice of Schema structs to a JSON-LD compatible format.
func serializeSchemas(schemas []Schema) interface{} {
	if len(schemas) == 0 {
		return nil
	}
	if len(schemas) == 1 {
		return serializeSchema(schemas[0])
	}
	return mapSlice(schemas, serializeSchema)
}

// serializeSchema converts a single Schema struct to a JSON object.
func serializeSchema(schema Schema) JSONMap {
	return JSONMap{
		jsonFldSchemaID:   schema.ID,
		jsonFldSchemaType: schema.Type,
	}
}

// serializeStatuses converts a slice of Status structs to a JSON-LD compatible format.
func serializeStatuses(statuses []Status) interface{} {
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

// serializeContexts validates and converts a slice of JSON-LD context entries.
func serializeContexts(contexts []interface{}) ([]interface{}, error) {
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

// mapSlice transforms a slice of type T to a slice of type U using a mapping function.
func mapSlice[T any, U any](slice []T, mapFn func(T) U) []U {
	result := make([]U, 0, len(slice))
	for _, v := range slice {
		result = append(result, mapFn(v))
	}
	return result
}

// parseRawToProof converts an interface{} (JSON object) to a Proof struct.
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
	return result, nil
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
		schemaID, err := parseSchemaID(schema)
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

// parseSchemaID parses a Schema from a value.
func parseSchemaID(value interface{}) (Schema, error) {
	var schema Schema
	switch v := value.(type) {
	case string:
		schema.ID = v
	case map[string]interface{}:
		if id, ok := v["id"].(string); ok {
			schema.ID = id
		}
		if t, ok := v["type"].(string); ok {
			schema.Type = t
		}
	default:
		return schema, fmt.Errorf("failed to parse schema ID: invalid format %T", value)
	}
	return schema, nil
}

// parseSchema extracts the credentialSchema field from a Credential.
func parseProofs(c *Credential, contents *CredentialContents) error {
	if proof, ok := (*c)["proof"].(map[string]interface{}); ok {
		pro, err := parseProof(proof)
		if err != nil {
			return fmt.Errorf("failed to parse schema: %w", err)
		}
		contents.Proofs = append(contents.Proofs, pro)
	}
	return nil
}

// parseProof converts a single proof map into a Proof struct.
func parseProof(proof map[string]interface{}) (Proof, error) {
	var result Proof
	if t, ok := proof["type"].(string); ok && t != "" {
		result.Type = t
	} else {
		return Proof{}, fmt.Errorf("failed to parse proof: invalid or missing type field")
	}
	if created, ok := proof["created"].(string); ok && created != "" {
		result.Created = created
	} else {
		return Proof{}, fmt.Errorf("failed to parse proof: invalid or missing created field")
	}
	if vm, ok := proof["verificationMethod"].(string); ok && vm != "" {
		result.VerificationMethod = vm
	} else {
		return Proof{}, fmt.Errorf("failed to parse proof: invalid or missing verificationMethod field")
	}
	if pp, ok := proof["proofPurpose"].(string); ok && pp != "" {
		result.ProofPurpose = pp
	} else {
		return Proof{}, fmt.Errorf("failed to parse proof: invalid or missing proofPurpose field")
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
