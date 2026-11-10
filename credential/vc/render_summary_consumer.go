package vc

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// RenderOptions controls template retrieval for summary, HTML, and static
// render methods.
type RenderOptions struct {
	Fetcher Fetcher
	// MaxSummaryOutputBytes caps the total size of values RenderSummary copies
	// from the credential. Zero or less uses a 1 MiB default.
	MaxSummaryOutputBytes int
}

const defaultMaxSummaryOutputBytes = 1 << 20

// RenderSummary resolves and validates a summary render method without
// executing any template code. It returns the summary template with every JSON
// Pointer replaced by the value it selects from the credential.
func (m RenderMethod) RenderSummary(ctx context.Context, credential CredentialData, opts RenderOptions) (*SummaryTemplate, error) {
	if m.RenderSuite != "summary" {
		return nil, fmt.Errorf("render method suite must be summary")
	}
	if err := m.Validate(); err != nil {
		return nil, fmt.Errorf("invalid summary render method: %w", err)
	}
	data, err := templateBytes(ctx, m, opts.Fetcher)
	if err != nil {
		return nil, err
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("decode summary template: %w", err)
	}
	budget := opts.MaxSummaryOutputBytes
	if budget <= 0 {
		budget = defaultMaxSummaryOutputBytes
	}
	if _, err := resolveNode(raw, credential, false, true, &budget); err != nil {
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
	if err := requireSummaryMembers(resolved); err != nil {
		return nil, fmt.Errorf("invalid resolved summary output: %w", err)
	}
	return &output, nil
}

func templateBytes(ctx context.Context, method RenderMethod, fetcher Fetcher) ([]byte, error) {
	if method.Template == nil {
		return nil, fmt.Errorf("%s template is required", method.RenderSuite)
	}
	if method.Template.Embedded != nil {
		return method.Template.Embedded.Bytes, nil
	}
	ref := *method.Template.Reference
	var data []byte
	if isDataURL(ref.ID) {
		embedded, err := decodeDataURL(ref.ID)
		if err != nil {
			return nil, fmt.Errorf("decode %s template: %w", method.RenderSuite, err)
		}
		data = embedded.Bytes
		if ref.MediaType == "" {
			ref.MediaType = embedded.MediaType
		}
	} else {
		if fetcher == nil {
			return nil, fmt.Errorf("template fetcher is required for external %s template", method.RenderSuite)
		}
		var err error
		data, err = fetcher.Fetch(ctx, ref)
		if err != nil {
			return nil, fmt.Errorf("fetch %s template: %w", method.RenderSuite, err)
		}
	}
	if ref.DigestMultibase != "" {
		if err := verifyDigestMultibase(data, ref.DigestMultibase); err != nil {
			return nil, fmt.Errorf("verify %s template digest: %w", method.RenderSuite, err)
		}
	}
	// A referenced template is not covered by the credential signature, so it
	// must pass the same content rules as an embedded one before use.
	if err := method.validateFetchedTemplate(ref, data); err != nil {
		return nil, fmt.Errorf("invalid external %s template: %w", method.RenderSuite, err)
	}
	return data, nil
}

func resolveNode(value any, credential CredentialData, literal, required bool, budget *int) (any, error) {
	switch v := value.(type) {
	case map[string]any:
		for key, child := range v {
			childRequired := required && (key == "name" || key == "description" || key == "fields" || key == "label" || key == "value")
			resolved, err := resolveNode(child, credential, key == "label", childRequired, budget)
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
			resolved, err := resolveNode(child, credential, literal, required, budget)
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
		resolved, err := resolveJSONPointer(map[string]any(credential), v)
		if err != nil {
			if !required {
				return nil, nil
			}
			return nil, err
		}
		// A pointer that lands on JSON null has no value to show: treat it like a
		// missing pointer, so an optional member is omitted and a required one
		// fails, instead of rendering the word "null".
		if resolved == nil {
			if !required {
				return nil, nil
			}
			return nil, fmt.Errorf("JSON Pointer %q resolves to null", v)
		}
		text := ""
		if s, ok := resolved.(string); ok {
			text = s
		} else {
			var encoded strings.Builder
			encoder := json.NewEncoder(&encoded)
			encoder.SetEscapeHTML(false)
			if err := encoder.Encode(resolved); err != nil {
				return nil, fmt.Errorf("encode pointer value %q: %w", v, err)
			}
			text = strings.TrimSuffix(encoded.String(), "\n")
		}
		*budget -= len(text)
		if *budget < 0 {
			return nil, fmt.Errorf("summary output exceeds the size limit; raise RenderOptions.MaxSummaryOutputBytes to accept it")
		}
		return text, nil
	default:
		return value, nil
	}
}
