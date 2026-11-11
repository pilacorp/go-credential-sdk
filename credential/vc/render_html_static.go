package vc

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/pilacorp/go-credential-sdk/credential/common/jsonmap"
)

// HTMLRenderArtifact is the wrapper document for an HTML render method. The SDK
// never executes it. SrcDoc already contains the wrapper side of WD-20261013
// §2.2.2.2.3 (the port listener and window.renderMethodReady); the host page owns the
// rest: the sandboxed iframe, its own CSP, the MessageChannel, and waiting for
// the ready or error message.
type HTMLRenderArtifact struct {
	SrcDoc string
	// Width and Height are raw credential values: assign them through
	// element.style, never into HTML or a style attribute string.
	Width  string
	Height string
}

// WrapHTMLTemplate validates an HTML render method and returns its srcdoc. The
// SDK does not isolate it: the host must load SrcDoc in an iframe with
// sandbox="allow-scripts", never allow-same-origin, on a page whose CSP includes
// frame-src 'none' (WD-20261013 §2.2.2.2).
func (m RenderMethod) WrapHTMLTemplate(ctx context.Context, credential CredentialData, opts RenderOptions) (*HTMLRenderArtifact, error) {
	if m.RenderSuite != "html" {
		return nil, fmt.Errorf("render method suite must be html")
	}
	if err := m.validateInCredential(); err != nil {
		return nil, fmt.Errorf("invalid html render method: %w", err)
	}
	template, _, err := templateBytes(ctx, m, opts.Fetcher)
	if err != nil {
		return nil, err
	}
	filtered, err := selectCredential(credential, m.RenderProperty)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(filtered)
	if err != nil {
		return nil, fmt.Errorf("encode filtered credential: %w", err)
	}
	// json.Marshal writes <, >, &, U+2028 and U+2029 inside strings as \u
	// escapes, so the data cannot close the <script> block it sits in.
	// This follows the TR wrapper shape: the data block and the wrapper script
	// are in <head>, so window.renderMethodReady exists before the template in
	// <body> runs. The host page creates the MessageChannel and waits for the
	// ready or error message.
	srcdoc := `<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src data: 'unsafe-inline'"><script name="credential" type="application/vc">` + string(data) + `</script><script>` + renderMethodReadySetup + `</script></head><body>` + string(template) + `</body></html>`
	artifact := &HTMLRenderArtifact{SrcDoc: srcdoc}
	if m.OutputPreference != nil && m.OutputPreference.Style != nil {
		artifact.Width = m.OutputPreference.Style.Width
		artifact.Height = m.OutputPreference.Style.Height
	}
	return artifact, nil
}

// renderMethodReadySetup is the wrapper script of WD-20261013 §2.2.2.2.3
// Example 12, which §3.2.2 requires. It receives the MessageChannel port the
// host page sends with a "start" message and defines window.renderMethodReady,
// which the template calls with no argument when rendering is complete, or with
// an Error when it fails.
const renderMethodReadySetup = `const portPromise = new Promise(resolve => {
  window.addEventListener('message', function start(event) {
    if(event.data === 'start' && event.ports?.[0]) {
      window.removeEventListener('message', start);
      resolve(event.ports[0]);
    }
  });
});
window.renderMethodReady = function(err) {
  portPromise.then(port => port.postMessage(
    !err ? 'ready' : {error: {message: err.message}}));
};`

// StaticOutput contains a static payload and its delivery metadata.
type StaticOutput struct {
	Bytes        []byte
	MediaType    string
	DeliveryMode string
	Credential   CredentialData
}

// ResolveStatic resolves a static render method without interpreting its bytes.
// Fetched bytes are checked against digestMultibase only when the template has
// one.
func (m RenderMethod) ResolveStatic(ctx context.Context, credential CredentialData, opts RenderOptions) (*StaticOutput, error) {
	if m.RenderSuite != "static" {
		return nil, fmt.Errorf("render method suite must be static")
	}
	if err := m.validateInCredential(); err != nil {
		return nil, fmt.Errorf("invalid static render method: %w", err)
	}
	data, mediaType, err := templateBytes(ctx, m, opts.Fetcher)
	if err != nil {
		return nil, err
	}
	filtered, err := selectCredential(credential, m.RenderProperty)
	if err != nil {
		return nil, err
	}
	return &StaticOutput{Bytes: data, MediaType: mediaType, DeliveryMode: m.DeliveryMode, Credential: filtered}, nil
}

func selectCredential(credential CredentialData, pointers []string) (CredentialData, error) {
	if pointers == nil {
		return credential, nil
	}
	selected, err := jsonmap.SelectJSONLD(map[string]interface{}(credential), pointers)
	if err != nil {
		return nil, fmt.Errorf("select render properties: %w", err)
	}
	return CredentialData(selected), nil
}
