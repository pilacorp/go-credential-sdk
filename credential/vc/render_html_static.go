package vc

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"strings"
)

// HTMLRenderArtifact is safe-to-hand-off HTML source. The SDK never executes it.
type HTMLRenderArtifact struct {
	SrcDoc string
	Width  string
	Height string
}

// RenderHTML validates an HTML render method and prepares an isolated srcdoc.
func RenderHTML(ctx context.Context, credential CredentialData, method RenderMethod, opts SummaryOptions) (*HTMLRenderArtifact, error) {
	if method.RenderSuite != "html" {
		return nil, fmt.Errorf("render method suite must be html")
	}
	if err := method.Validate(); err != nil {
		return nil, fmt.Errorf("invalid html render method: %w", err)
	}
	template, err := templateBytes(ctx, method, opts.Fetcher)
	if err != nil {
		return nil, err
	}
	lower := strings.ToLower(string(template))
	for _, tag := range []string{"<html", "<head", "<body"} {
		if strings.Contains(lower, tag) {
			return nil, fmt.Errorf("html template must be a fragment without %s element", tag[:len(tag)-1])
		}
	}
	filtered, err := selectCredential(credential, method.RenderProperty)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(filtered)
	if err != nil {
		return nil, fmt.Errorf("encode filtered credential: %w", err)
	}
	srcdoc := `<!doctype html><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; style-src 'unsafe-inline'; script-src 'unsafe-inline'"><script>window.addEventListener('error',()=>parent.postMessage({type:'error'},'*'));window.parent.postMessage({type:'ready'},'*')</script><script type="application/vc+json" id="vc-data">` + html.EscapeString(string(data)) + `</script>` + string(template)
	artifact := &HTMLRenderArtifact{SrcDoc: srcdoc}
	if method.OutputPreference != nil && method.OutputPreference.Style != nil {
		artifact.Width = method.OutputPreference.Style.Width
		artifact.Height = method.OutputPreference.Style.Height
	}
	return artifact, nil
}

// StaticOutput contains a verified static payload and its delivery metadata.
type StaticOutput struct {
	Bytes        []byte
	MediaType    string
	DeliveryMode string
	Credential   CredentialData
}

// ResolveStatic resolves and verifies a static render method without interpreting its bytes.
func ResolveStatic(ctx context.Context, credential CredentialData, method RenderMethod, opts SummaryOptions) (*StaticOutput, error) {
	if method.RenderSuite != "static" {
		return nil, fmt.Errorf("render method suite must be static")
	}
	if err := method.Validate(); err != nil {
		return nil, fmt.Errorf("invalid static render method: %w", err)
	}
	data, err := templateBytes(ctx, method, opts.Fetcher)
	if err != nil {
		return nil, err
	}
	filtered, err := selectCredential(credential, method.RenderProperty)
	if err != nil {
		return nil, err
	}
	mediaType := ""
	if method.Template != nil {
		if method.Template.Embedded != nil {
			mediaType = method.Template.Embedded.MediaType
		} else if method.Template.Reference != nil {
			mediaType = method.Template.Reference.MediaType
		}
	}
	return &StaticOutput{Bytes: data, MediaType: mediaType, DeliveryMode: method.DeliveryMode, Credential: filtered}, nil
}

func selectCredential(credential CredentialData, pointers []string) (CredentialData, error) {
	if len(pointers) == 0 {
		return credential, nil
	}
	out := CredentialData{}
	for _, pointer := range pointers {
		value, err := ResolveJSONPointer(map[string]any(credential), pointer)
		if err != nil {
			return nil, fmt.Errorf("renderProperty %q: %w", pointer, err)
		}
		if err := setPointer(out, pointer, value); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func setPointer(document CredentialData, pointer string, value any) error {
	parts := strings.Split(pointer[1:], "/")
	current := map[string]any(document)
	for i, part := range parts {
		key := strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
		if i == len(parts)-1 {
			current[key] = value
			return nil
		}
		next, ok := current[key].(map[string]any)
		if !ok {
			next = map[string]any{}
			current[key] = next
		}
		current = next
	}
	return nil
}
