package vc

import (
	"encoding/json"
	"fmt"
)

// CredentialSchemaLoader is an implementation of gojsonschema.JSONLoader for fetching credential schemas.
type CredentialSchemaLoader struct {
	Schema string
}

// LoadJSON loads the schema as a JSON interface.
func (l *CredentialSchemaLoader) LoadJSON() (interface{}, error) {
	var result interface{}
	err := json.Unmarshal([]byte(l.Schema), &result)
	if err != nil {
		return nil, fmt.Errorf("unmarshal schema: %w", err)
	}
	return result, nil
}

// JsonSource returns the JSON source (schema string).
func (l *CredentialSchemaLoader) JsonSource() interface{} {
	return l.Schema
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
