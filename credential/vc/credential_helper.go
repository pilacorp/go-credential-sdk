package vc

import (
	"fmt"
	"time"

	"github.com/xeipuuv/gojsonschema"

	"github.com/pilacorp/go-credential-sdk/credential/common/jsonmap"
	"github.com/pilacorp/go-credential-sdk/credential/common/processor"
	"github.com/pilacorp/go-credential-sdk/credential/common/util"
)

// serializeCredentialContents serializes CredentialContents into a Credential.
func serializeCredentialContents(vcc *CredentialContents) (jsonmap.JSONMap, error) {
	if vcc == nil {
		return nil, fmt.Errorf("credential contents is nil")
	}

	vcJSON := make(jsonmap.JSONMap)
	if len(vcc.Context) > 0 {
		validatedContext, err := util.SerializeContexts(vcc.Context)
		if err != nil {
			return nil, fmt.Errorf("invalid @context: %w", err)
		}
		vcJSON["@context"] = validatedContext
	}
	if vcc.ID != "" {
		vcJSON["id"] = vcc.ID
	}
	if len(vcc.Types) > 0 {
		vcJSON["type"] = util.SerializeTypes(vcc.Types)
	}
	if len(vcc.Subject) > 0 {
		vcJSON["credentialSubject"] = serializeSubjects(vcc.Subject)
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

// serializeSubjects converts a slice of Subject structs to a JSON-LD compatible format.
func serializeSubjects(subjects []Subject) interface{} {
	if len(subjects) == 0 {
		return nil
	}
	if len(subjects) == 1 {
		return serializeSubject(subjects[0])
	}
	return util.MapSlice(subjects, serializeSubject)
}

// serializeSubject converts a single Subject struct to a JSON object.
func serializeSubject(subject Subject) jsonmap.JSONMap {
	jsonObj := util.ShallowCopyObj(subject.CustomFields)
	if subject.ID != "" {
		jsonObj["id"] = subject.ID
	}
	return jsonObj
}

// serializeSchemas converts a slice of Schema structs to a JSON-LD compatible format.
func serializeSchemas(schemas []Schema) interface{} {
	if len(schemas) == 0 {
		return nil
	}
	if len(schemas) == 1 {
		return serializeSchema(schemas[0])
	}
	return util.MapSlice(schemas, serializeSchema)
}

// serializeSchema converts a single Schema struct to a JSON object.
func serializeSchema(schema Schema) jsonmap.JSONMap {
	return jsonmap.JSONMap{
		"id":   schema.ID,
		"type": schema.Type,
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
	return util.MapSlice(statuses, serializeStatus)
}

// serializeStatus converts a single Status struct to a JSON object.
func serializeStatus(status Status) jsonmap.JSONMap {
	result := make(jsonmap.JSONMap)
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

// parseContext extracts the @context field from a Credential.
func parseContext(c JSONCredential, contents *CredentialContents) error {
	if context, ok := c["@context"].([]interface{}); ok {
		for _, ctx := range context {
			switch v := ctx.(type) {
			case string, map[string]interface{}:
				contents.Context = append(contents.Context, v)
			default:
				return fmt.Errorf("unsupported context type: %T", v)
			}
		}
	}
	return nil
}

// parseID extracts the ID field from a Credential.
func parseID(c JSONCredential, contents *CredentialContents) error {
	if id, ok := c["id"].(string); ok {
		contents.ID = id
	}
	return nil
}

// parseTypes extracts the type field from a Credential.
func parseTypes(c JSONCredential, contents *CredentialContents) error {
	switch v := c["type"].(type) {
	case string:
		contents.Types = append(contents.Types, v)
	case []interface{}:
		for _, t := range v {
			if typeStr, ok := t.(string); ok {
				contents.Types = append(contents.Types, typeStr)
			}
		}
	default:
		return fmt.Errorf("unsupported type field: %T", v)
	}
	return nil
}

// parseIssuer extracts the issuer field from a Credential.
func parseIssuer(c JSONCredential, contents *CredentialContents) error {
	if issuer, ok := c["issuer"].(string); ok {
		contents.Issuer = issuer
	}
	return nil
}

// parseDates extracts validFrom and validUntil fields from a Credential.
func parseDates(c JSONCredential, contents *CredentialContents) error {
	if validFrom, ok := c["validFrom"].(string); ok {
		t, err := time.Parse(time.RFC3339, validFrom)
		if err != nil {
			return fmt.Errorf("failed to parse validFrom: %w", err)
		}
		contents.ValidFrom = t
	}
	if validUntil, ok := c["validUntil"].(string); ok {
		t, err := time.Parse(time.RFC3339, validUntil)
		if err != nil {
			return fmt.Errorf("failed to parse validUntil: %w", err)
		}
		contents.ValidUntil = t
	}
	return nil
}

// parseSubject extracts the credentialSubject field from a Credential.
func parseSubject(c JSONCredential, contents *CredentialContents) error {
	subjectRaw := c["credentialSubject"]
	if subjectRaw == nil {
		return nil
	}

	switch subject := subjectRaw.(type) {
	case string:
		contents.Subject = []Subject{{ID: subject}}
	case map[string]interface{}:
		parsed, err := SubjectFromJSON(subject)
		if err != nil {
			return fmt.Errorf("failed to parse subject: %w", err)
		}
		contents.Subject = []Subject{parsed}
	case []interface{}:
		subjects := make([]Subject, 0, len(subject))
		for _, raw := range subject {
			sub, ok := raw.(map[string]interface{})
			if !ok {
				return fmt.Errorf("unsupported subject format: %T", raw)
			}
			parsed, err := SubjectFromJSON(sub)
			if err != nil {
				return fmt.Errorf("failed to parse subjects array: %w", err)
			}
			subjects = append(subjects, parsed)
		}
		contents.Subject = subjects
	default:
		return fmt.Errorf("unsupported subject format: %T", subject)
	}
	return nil
}

// SubjectFromJSON creates a credential subject from a JSON object.
func SubjectFromJSON(subjectObj jsonmap.JSONMap) (Subject, error) {
	flds, rest := util.SplitJSONObj(subjectObj, "id")
	id, err := parseStringField(flds, "id")
	if err != nil {
		return Subject{}, fmt.Errorf("failed to parse subject id: %w", err)
	}
	return Subject{ID: id, CustomFields: rest}, nil
}

// parseSchema extracts the credentialSchema field from a Credential.
func parseSchema(c JSONCredential, contents *CredentialContents) error {
	schemaRaw := c["credentialSchema"]
	if schemaRaw == nil {
		return nil
	}

	switch schema := schemaRaw.(type) {
	case map[string]interface{}:
		parsed, err := parseSchemaID(schema)
		if err != nil {
			return fmt.Errorf("failed to parse schema: %w", err)
		}
		contents.Schemas = append(contents.Schemas, parsed)
	case []interface{}:
		for _, raw := range schema {
			parsed, err := parseSchemaID(raw)
			if err != nil {
				return fmt.Errorf("failed to parse schema: %w", err)
			}
			contents.Schemas = append(contents.Schemas, parsed)
		}
	default:
		return fmt.Errorf("unsupported schema format: %T", schema)
	}
	return nil
}

// parseStatus extracts the credentialStatus field from a Credential.
func parseStatus(c JSONCredential, contents *CredentialContents) error {
	statusRaw := c["credentialStatus"]
	if statusRaw == nil {
		return nil
	}

	switch status := statusRaw.(type) {
	case map[string]interface{}:
		parsed, err := parseStatusEntry(status)
		if err != nil {
			return fmt.Errorf("failed to parse status: %w", err)
		}
		contents.CredentialStatus = append(contents.CredentialStatus, parsed)
	case []interface{}:
		for _, raw := range status {
			if statusMap, ok := raw.(map[string]interface{}); ok {
				parsed, err := parseStatusEntry(statusMap)
				if err != nil {
					return fmt.Errorf("failed to parse status: %w", err)
				}
				contents.CredentialStatus = append(contents.CredentialStatus, parsed)
			} else {
				return fmt.Errorf("unsupported status format: %T", raw)
			}
		}
	default:
		return fmt.Errorf("unsupported status format: %T", status)
	}
	return nil
}

// parseStatusEntry parses a single status entry from a JSON object.
func parseStatusEntry(status map[string]interface{}) (Status, error) {
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
	return s, nil
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
		return schema, fmt.Errorf("invalid schema format: %T", v)
	}
	return schema, nil
}

// parseProofs extracts the proof field from a Credential.
func parseProofs(c JSONCredential, contents *CredentialContents) error {
	proofRaw := c["proof"]
	if proofRaw == nil {
		return nil
	}

	// Note: Proofs are handled separately in the credential implementations
	// This function is kept for compatibility but doesn't populate contents.Proofs
	// since CredentialContents doesn't have a Proofs field
	return nil
}

// parseStringField extracts a string field from a JSON object.
func parseStringField(obj jsonmap.JSONMap, fieldName string) (string, error) {
	if value, ok := obj[fieldName]; ok {
		if str, ok := value.(string); ok {
			return str, nil
		}
		return "", fmt.Errorf("field %q must be a string, got %T", fieldName, value)
	}
	return "", nil
}

// validateCredential validates the Credential against its schema.
func validateCredential(m jsonmap.JSONMap, processor *processor.ProcessorOptions) error {
	if processor == nil {
		return fmt.Errorf("processor options are required")
	}

	requiredKeys := []string{"type", "credentialSchema", "credentialSubject", "credentialStatus", "proof"}
	for _, key := range requiredKeys {
		if _, exists := m[key]; !exists {
			return fmt.Errorf("%s is required", key)
		}
		m[key] = convertToArray(m[key])
	}

	for _, schema := range m["credentialSchema"].([]interface{}) {
		schemaMap, ok := schema.(map[string]interface{})
		if !ok || schemaMap["id"] == nil {
			return fmt.Errorf("credentialSchema.id is required")
		}

		schemaID, ok := schemaMap["id"].(string)
		if !ok || schemaID == "" {
			return fmt.Errorf("credentialSchema.id must be a non-empty string")
		}

		schemaLoader := gojsonschema.NewReferenceLoader(schemaID)
		credentialLoader := gojsonschema.NewGoLoader(m)

		result, err := gojsonschema.Validate(schemaLoader, credentialLoader)
		if err != nil {
			return fmt.Errorf("failed to validate schema: %w", err)
		}
		if !result.Valid() {
			return fmt.Errorf("credential validation failed: %v", result.Errors())
		}
	}
	return nil
}

// convertToArray ensures a value is represented as an array.
func convertToArray(value interface{}) []interface{} {
	if value == nil {
		return nil
	}
	if arr, ok := value.([]interface{}); ok {
		return arr
	}
	return []interface{}{value}
}
