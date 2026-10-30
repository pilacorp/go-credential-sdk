package vc

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// SummaryOptions controls summary template retrieval.
type SummaryOptions struct {
	Fetcher TemplateFetcher
}

// SummaryOutput is the resolved summary object returned to a client.
type SummaryOutput = SummaryTemplate

// RenderSummary resolves and validates a summary render method without
// executing any template code.
func RenderSummary(ctx context.Context, credential CredentialData, method RenderMethod, opts SummaryOptions) (*SummaryOutput, error) {
	if err := method.Validate(); err != nil {
		return nil, fmt.Errorf("invalid summary render method: %w", err)
	}
	data, err := templateBytes(ctx, method, opts.Fetcher)
	if err != nil {
		return nil, err
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("decode summary template: %w", err)
	}
	if _, err := resolveNode(raw, credential, false, true); err != nil {
		return nil, err
	}
	resolved, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("encode summary output: %w", err)
	}
	var output SummaryTemplate
	dec := json.NewDecoder(strings.NewReader(string(resolved)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&output); err != nil {
		return nil, fmt.Errorf("invalid resolved summary output: %w", err)
	}
	if output.Name == "" || output.Description == "" || len(output.Fields) == 0 {
		return nil, fmt.Errorf("summary output requires name, description, and at least one field")
	}
	return &output, nil
}

func templateBytes(ctx context.Context, method RenderMethod, fetcher TemplateFetcher) ([]byte, error) {
	if method.Template == nil {
		return nil, fmt.Errorf("summary template is required")
	}
	if method.Template.Embedded != nil {
		return method.Template.Embedded.Bytes, nil
	}
	if fetcher == nil {
		return nil, fmt.Errorf("template fetcher is required for external summary template")
	}
	data, err := fetcher.Fetch(ctx, *method.Template.Reference)
	if err != nil {
		return nil, fmt.Errorf("fetch summary template: %w", err)
	}
	if method.Template.Reference.DigestMultibase != "" {
		if err := VerifyDigestMultibase(data, method.Template.Reference.DigestMultibase); err != nil {
			return nil, fmt.Errorf("verify summary template digest: %w", err)
		}
	}
	return data, nil
}

func resolveNode(value any, credential CredentialData, literal, required bool) (any, error) {
	switch v := value.(type) {
	case map[string]any:
		for key, child := range v {
			childRequired := required && (key == "name" || key == "description" || key == "fields" || key == "label" || key == "value")
			resolved, err := resolveNode(child, credential, key == "label", childRequired)
			if err != nil {
				return nil, err
			}
			if resolved == nil {
				delete(v, key)
			} else {
				v[key] = resolved
			}
		}
		return v, nil
	case []any:
		for i, child := range v {
			resolved, err := resolveNode(child, credential, literal, required)
			if err != nil {
				return nil, err
			}
			v[i] = resolved
		}
		return v, nil
	case string:
		if literal || !strings.HasPrefix(v, "/") {
			return v, nil
		}
		resolved, err := ResolveJSONPointer(map[string]any(credential), v)
		if err != nil {
			if !required {
				return nil, nil
			}
			return nil, err
		}
		if s, ok := resolved.(string); ok {
			return s, nil
		}
		encoded, err := json.Marshal(resolved)
		if err != nil {
			return nil, fmt.Errorf("encode pointer value %q: %w", v, err)
		}
		return string(encoded), nil
	default:
		return value, nil
	}
}
