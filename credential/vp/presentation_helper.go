package vp

import (
	"encoding/json"
	"fmt"

	"github.com/pilacorp/go-credential-sdk/credential/common/jsonmap"
	"github.com/pilacorp/go-credential-sdk/credential/common/util"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
)

// verifyCredentials verifies the signatures of a slice of Verifiable Credentials.
func verifyCredentials(vcs []vc.Credential) error {
	if vcs == nil {
		return fmt.Errorf("credential input is nil")
	}

	for i, v := range vcs {
		if v == nil {
			return fmt.Errorf("credential at index %d is nil", i)
		}
		// Verify the credential using the new interface
		err := v.Verify(vc.WithBaseURL(config.BaseURL))
		if err != nil {
			return fmt.Errorf("failed to verify credential at index %d: %w", i, err)
		}
	}
	return nil
}

// serializePresentationContents serializes PresentationContents into a JSON map.
func serializePresentationContents(vpc *PresentationContents) (jsonmap.JSONMap, error) {
	if vpc == nil {
		return nil, fmt.Errorf("presentation contents is nil")
	}

	vpJSON := make(jsonmap.JSONMap)

	if len(vpc.Context) > 0 {
		validatedContext, err := util.SerializeContexts(vpc.Context)
		if err != nil {
			return nil, fmt.Errorf("invalid @context: %w", err)
		}
		vpJSON["@context"] = validatedContext
	}
	if vpc.ID != "" {
		vpJSON["id"] = vpc.ID
	}
	if len(vpc.Types) > 0 {
		vpJSON["type"] = util.SerializeTypes(vpc.Types)
	}
	if vpc.Holder != "" {
		vpJSON["holder"] = vpc.Holder
	}
	if len(vpc.VerifiableCredentials) > 0 {
		// Serialize credentials for presentation storage
		credentialList := make([]interface{}, len(vpc.VerifiableCredentials))
		for i, vc := range vpc.VerifiableCredentials {
			// Use Serialize() method which returns the appropriate format for each credential type
			serialized, err := vc.Serialize()
			if err != nil {
				return nil, fmt.Errorf("failed to serialize credential %d: %w", i, err)
			}
			credentialList[i] = serialized
			err = vc.Verify()
			if err != nil {
				return nil, fmt.Errorf("failed to verify credential %d: %w", i, err)
			}
		}
		vpJSON["verifiableCredential"] = credentialList
	}

	return vpJSON, nil
}

// parseContext extracts the @context field from a Presentation.
func parseContext(vp JSONPresentation, contents *PresentationContents) error {
	if context, ok := vp["@context"].([]interface{}); ok {
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

// parseID extracts the ID field from a Presentation.
func parseID(vp JSONPresentation, contents *PresentationContents) error {
	if id, ok := vp["id"].(string); ok {
		contents.ID = id
	}
	return nil
}

// parseTypes extracts the type field from a Presentation.
func parseTypes(vp JSONPresentation, contents *PresentationContents) error {
	switch v := vp["type"].(type) {
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

// parseHolder extracts the holder field from a Presentation.
func parseHolder(vp JSONPresentation, contents *PresentationContents) error {
	if holder, ok := vp["holder"].(string); ok {
		contents.Holder = holder
	}
	return nil
}

// parseVerifiableCredentials extracts the verifiableCredential field from a Presentation.
func parseVerifiableCredentials(vp JSONPresentation, contents *PresentationContents) error {
	vcs, ok := vp["verifiableCredential"].([]interface{})
	if !ok {
		return nil // No verifiable credentials field
	}

	for i, vcItem := range vcs {
		if vcItem == nil {
			return fmt.Errorf("credential at index %d is nil", i)
		}

		// Marshal to bytes (handles both strings and objects)
		vcItemBytes, err := json.Marshal(vcItem)
		if err != nil {
			return fmt.Errorf("failed to marshal credential at index %d: %w", i, err)
		}

		// Parse using the unified ParseCredential function
		credential, err := vc.ParseCredential(vcItemBytes, vc.WithDisableValidation())
		if err != nil {
			return fmt.Errorf("failed to parse credential at index %d: %w", i, err)
		}
		contents.VerifiableCredentials = append(contents.VerifiableCredentials, credential)
	}
	return nil
}

// parseProofs extracts the proof field from a Presentation.
func parseProofs(vp JSONPresentation, contents *PresentationContents) error {
	proofRaw := vp["proof"]
	if proofRaw == nil {
		return nil
	}

	return nil
}

// parsePresentationContents parses the Presentation into structured contents.
func parsePresentationContents(vp JSONPresentation) (PresentationContents, error) {
	var contents PresentationContents
	parsers := []func(JSONPresentation, *PresentationContents) error{
		parseContext,
		parseID,
		parseTypes,
		parseHolder,
		parseVerifiableCredentials,
		parseProofs,
	}

	for _, parser := range parsers {
		if err := parser(vp, &contents); err != nil {
			return contents, fmt.Errorf("failed to parse presentation contents: %w", err)
		}
	}
	return contents, nil
}
