package vc

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/pilacorp/go-credential-sdk/credential/common/jsonmap"
)

// HTMLRenderArtifact is safe-to-hand-off HTML source. The SDK never executes it
// or owns the browser host lifecycle. The client is responsible for sandboxing
// the iframe and handling render completion or errors.
type HTMLRenderArtifact struct {
	SrcDoc string
	Width  string
	Height string
}

// WrapHTMLTemplate validates an HTML render method and prepares an isolated srcdoc.
func WrapHTMLTemplate(ctx context.Context, credential CredentialData, method RenderMethod, opts RenderOptions) (*HTMLRenderArtifact, error) {
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
	for _, tag := range []string{"html", "head", "body"} {
		if containsHTMLElement(string(template), tag) {
			return nil, fmt.Errorf("html template must be a fragment without <%s> element", tag)
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
	credentialJSON := escapeScriptData(string(data))
	// This follows the TR wrapper shape: the data block is in <head> and the
	// payload fragment is in <body>. The SDK deliberately does not inject
	// ready/error messaging; the client owns the iframe, MessageChannel, and
	// render lifecycle.
	srcdoc := `<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src data: 'unsafe-inline'"><script name="credential" type="application/vc">` + credentialJSON + `</script></head><body>` + string(template) + `</body></html>`
	artifact := &HTMLRenderArtifact{SrcDoc: srcdoc}
	if method.OutputPreference != nil && method.OutputPreference.Style != nil {
		artifact.Width = method.OutputPreference.Style.Width
		artifact.Height = method.OutputPreference.Style.Height
	}
	return artifact, nil
}

func escapeScriptData(value string) string {
	return strings.NewReplacer(
		"<", "\\u003c",
		">", "\\u003e",
		"&", "\\u0026",
		"\u2028", "\\u2028",
		"\u2029", "\\u2029",
	).Replace(value)
}

// StaticOutput contains a verified static payload and its delivery metadata.
type StaticOutput struct {
	Bytes        []byte
	MediaType    string
	DeliveryMode string
	Credential   CredentialData
}

// ResolveStatic resolves and verifies a static render method without interpreting its bytes.
func ResolveStatic(ctx context.Context, credential CredentialData, method RenderMethod, opts RenderOptions) (*StaticOutput, error) {
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
	selected, err := jsonmap.SelectJSONLD(map[string]interface{}(credential), pointers)
	if err != nil {
		return nil, fmt.Errorf("select render properties: %w", err)
	}
	return CredentialData(selected), nil
}

func setPointer(document CredentialData, pointer string, value any) error {
	if pointer == "" {
		return fmt.Errorf("root renderProperty cannot be inserted into a filtered credential")
	}
	parts := strings.Split(pointer[1:], "/")
	_, err := setPointerValue(map[string]any(document), parts, value)
	return err
}

func setPointerValue(current any, parts []string, value any) (any, error) {
	if len(parts) == 0 {
		return value, nil
	}

	token := strings.ReplaceAll(strings.ReplaceAll(parts[0], "~1", "/"), "~0", "~")
	switch node := current.(type) {
	case map[string]any:
		child, ok := node[token]
		if !ok || child == nil {
			child = newPointerContainer(parts[1:])
		}
		updated, err := setPointerValue(child, parts[1:], value)
		if err != nil {
			return nil, err
		}
		node[token] = updated
		return node, nil
	case []any:
		index, err := strconv.Atoi(token)
		if err != nil || index < 0 {
			return nil, fmt.Errorf("invalid array index %q in renderProperty", token)
		}
		for len(node) <= index {
			node = append(node, nil)
		}
		if node[index] == nil {
			node[index] = newPointerContainer(parts[1:])
		}
		updated, err := setPointerValue(node[index], parts[1:], value)
		if err != nil {
			return nil, err
		}
		node[index] = updated
		return node, nil
	default:
		return nil, fmt.Errorf("cannot insert renderProperty segment %q into %T", token, current)
	}
}

func newPointerContainer(remaining []string) any {
	if len(remaining) > 0 {
		if _, err := strconv.Atoi(strings.ReplaceAll(strings.ReplaceAll(remaining[0], "~1", "/"), "~0", "~")); err == nil {
			return []any{}
		}
	}
	return map[string]any{}
}
