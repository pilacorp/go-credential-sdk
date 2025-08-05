package vp

import (
	"fmt"

	"github.com/pilacorp/go-credential-sdk/credential/common/jsonmap"
	"github.com/pilacorp/go-credential-sdk/credential/common/util"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
)

// verifyCredentials verifies the ECDSA signatures of a slice of Verifiable Credentials.
func verifyCredentials(vcs []*vc.Credential) error {
	if vcs == nil {
		return fmt.Errorf("credential input is nil")
	}

	for i, v := range vcs {
		if v == nil {
			return fmt.Errorf("credential at index %d is nil", i)
		}
		vcSerialized, err := v.ToJSON()
		if err != nil {
			return fmt.Errorf("failed to serialize credential at index %d: %w", i, err)
		}
		verifyVC, err := vc.ParseCredential(vcSerialized, vc.WithDisableValidation())
		if err != nil {
			return fmt.Errorf("failed to parse credential at index %d: %w", i, err)
		}
		isValid, err := vc.VerifyECDSACredential(verifyVC, vc.WithBaseURL(config.BaseURL))
		if err != nil {
			return fmt.Errorf("failed to verify ECDSA proof for credential at index %d: %w", i, err)
		}
		if !isValid {
			return fmt.Errorf("ECDSA proof for credential at index %d is invalid", i)
		}
	}
	return nil
}

// serializePresentationContents serializes PresentationContents into a Presentation.
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
		if err := verifyCredentials(vpc.VerifiableCredentials); err != nil {
			return nil, fmt.Errorf("failed to verify credentials: %w", err)
		}
		vpJSON["verifiableCredential"] = vpc.VerifiableCredentials
	}
	if len(vpc.Proofs) > 0 {
		vpJSON["proof"] = util.SerializeProofs(vpc.Proofs)
	}
	return vpJSON, nil
}

// parseContext extracts the @context field from a Presentation.
func parseContext(vp *Presentation, contents *PresentationContents) error {
	if context, ok := (*vp)["@context"].([]interface{}); ok {
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
func parseID(vp *Presentation, contents *PresentationContents) error {
	if id, ok := (*vp)["id"].(string); ok {
		contents.ID = id
	}
	return nil
}

// parseTypes extracts the type field from a Presentation.
func parseTypes(vp *Presentation, contents *PresentationContents) error {
	switch v := (*vp)["type"].(type) {
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
func parseHolder(vp *Presentation, contents *PresentationContents) error {
	if holder, ok := (*vp)["holder"].(string); ok {
		contents.Holder = holder
	}
	return nil
}

// parseVerifiableCredentials extracts the verifiableCredential field from a Presentation.
func parseVerifiableCredentials(vp *Presentation, contents *PresentationContents) error {
	if vcs, ok := (*vp)["verifiableCredential"].([]interface{}); ok {
		for _, vcItem := range vcs {
			if vcMap, ok := vcItem.(map[string]interface{}); ok {
				credential := vc.Credential(vcMap)
				contents.VerifiableCredentials = append(contents.VerifiableCredentials, &credential)
			} else {
				return fmt.Errorf("unsupported credential format: %T", vcItem)
			}
		}
	}
	return nil
}

// parseProofs extracts the proof field from a Presentation.
func parseProofs(vp *Presentation, contents *PresentationContents) error {
	proofRaw := (*vp)["proof"]
	if proofRaw == nil {
		return nil
	}

	switch proof := proofRaw.(type) {
	case map[string]interface{}:
		parsed, err := jsonmap.ParseRawToProof(proof)
		if err != nil {
			return fmt.Errorf("failed to parse proof: %w", err)
		}
		contents.Proofs = append(contents.Proofs, parsed)
	case []interface{}:
		for _, raw := range proof {
			parsed, err := jsonmap.ParseRawToProof(raw)
			if err != nil {
				return fmt.Errorf("failed to parse proof: %w", err)
			}
			contents.Proofs = append(contents.Proofs, parsed)
		}
	default:
		return fmt.Errorf("unsupported proof format: %T", proof)
	}
	return nil
}
