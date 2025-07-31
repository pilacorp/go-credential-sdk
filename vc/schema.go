package vc

import (
	"encoding/json"
	"fmt"
)

// CredentialSchemaLoader loads and validates credential schemas for verifiable credentials.
type CredentialSchemaLoader struct {
	Schema string // JSON schema string
}

// LoadJSON loads the schema as a JSON interface.
func (loader *CredentialSchemaLoader) LoadJSON() (interface{}, error) {
	if loader.Schema == "" {
		return nil, fmt.Errorf("failed to load schema: schema string is empty")
	}
	var result interface{}
	if err := json.Unmarshal([]byte(loader.Schema), &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal schema: %w", err)
	}
	return result, nil
}

// JsonSource returns the JSON source (schema string).
func (loader *CredentialSchemaLoader) JsonSource() interface{} {
	return loader.Schema
}

// WithCredentialSchemaLoader returns a CredentialOpt that sets a custom schema loader.
func WithCredentialSchemaLoader(id, schema string) CredentialOpt {
	return func(c *credentialOptions) {
		if c.processor == nil {
			c.processor = &ProcessorOptions{}
		}
		c.processor.schemaLoader = &CredentialSchemaLoader{Schema: schema}
	}
}
