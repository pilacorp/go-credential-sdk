package vc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"mime"
	"net/url"
	"strings"

	whatwgurl "github.com/nlnwa/whatwg-url/url"
	"github.com/pilacorp/go-credential-sdk/credential/common/processor"
)

// RenderMethod is a SuiteRenderMethod entry of W3C VC Rendering Methods,
// Working Draft 2026-10-13, §2.2:
// https://www.w3.org/TR/2026/WD-vc-render-method-20261013/
//
// The JSON member names are part of the signed credential and follow that
// draft. Experimental: the draft can change, and this API changes with it.
//
// RenderProperty lists RFC 6901 JSON Pointers to the data a template sees: nil
// passes the whole credential, an empty list passes nothing, and the pointer ""
// selects the whole document. omitzero keeps an empty list on the wire, so it
// does not read back as nil.
type RenderMethod struct {
	// ID is the optional renderMethod.id (WD-20261013 §2.2). Rendering uses
	// Template, even when ID is present. To render from ID, call Dereference and
	// render the method it returns.
	ID               string            `json:"id,omitempty"`
	Type             string            `json:"type"`
	RenderSuite      string            `json:"renderSuite"`
	Name             string            `json:"name,omitempty"`
	Description      string            `json:"description,omitempty"`
	RenderProperty   []string          `json:"renderProperty,omitzero"`
	Template         *Template         `json:"template,omitempty"`
	DigestMultibase  string            `json:"digestMultibase,omitempty"`
	OutputPreference *OutputPreference `json:"outputPreference,omitempty"`
	DeliveryMode     string            `json:"deliveryMode,omitempty"`
}

// ParseRenderMethods reads the renderMethod member of a credential, given as
// one object or an array, and returns the entries this SDK can render, in
// document order. That order is not the issuer's preference: the VC context does
// not declare renderMethod as @list, so a Data Integrity proof does not cover it.
// Call it after Verify and after the context validation of VC Data Integrity
// 1.0 §4.6 (@context deeply equals a known value, no subtree contains @context,
// and every context URL resolves to a known file or hash): it checks neither
// the proof nor the contexts.
//
// Entries whose type is not SuiteRenderMethod, whose renderSuite is not
// summary, html or static, or that have neither a template nor an id are
// skipped, as WD-20261013 §2.2 requires
// for suites a consumer does not support. A supported entry that fails to
// decode or has an invalid format is an error, reported with its index.
// Template content is not read here: a renderer checks it, and Validate checks
// it before signing, so one entry with a broken template does not hide the
// others.
//
// When the credential embeds a proof, its JSON-LD is expanded first, and a
// credential with a term the @context does not define is refused. This is not
// a coverage check: a context with @vocab defines every term, and the result
// still relies on the VC Data Integrity 1.0 §4.6 check above. A credential
// secured outside the document, such as JOSE, has no proof member and skips
// that step.
func ParseRenderMethods(data CredentialData) ([]RenderMethod, error) {
	raw, ok := data["renderMethod"]
	if !ok || raw == nil {
		return nil, nil
	}
	if _, embeddedProof := data["proof"]; embeddedProof {
		// SafeMode refuses a term the @context does not define.
		if _, err := processor.ExpandJSONLD(normalizeCredentialData(data)); err != nil {
			return nil, fmt.Errorf("expand credential with renderMethod: %w", err)
		}
	}
	entries, ok := raw.([]any)
	if !ok {
		entries = []any{raw}
	}
	var methods []RenderMethod
	for i, entry := range entries {
		object, ok := entry.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("renderMethod[%d] must be an object", i)
		}
		if !isSupportedRenderMethod(object) {
			continue
		}
		encoded, err := json.Marshal(object)
		if err != nil {
			return nil, fmt.Errorf("renderMethod[%d]: %w", i, err)
		}
		var method RenderMethod
		if err := json.Unmarshal(encoded, &method); err != nil {
			return nil, fmt.Errorf("renderMethod[%d]: %w", i, err)
		}
		if err := method.validateFormat(); err != nil {
			return nil, fmt.Errorf("renderMethod[%d]: %w", i, err)
		}
		methods = append(methods, method)
	}
	return methods, nil
}

// isSupportedRenderMethod skips what WD-20261013 §2.2 tells a consumer to
// ignore. Entries with only an id are retained for Dereference.
func isSupportedRenderMethod(entry map[string]any) bool {
	if entry["type"] != "SuiteRenderMethod" {
		return false
	}
	suite, _ := entry["renderSuite"].(string)
	// A null template is no template: indexing covers absent and null alike.
	return isSupportedRenderSuite(suite) && (entry["template"] != nil || entry["id"] != nil)
}

// Dereference fetches the render method at ID with the fetcher the consumer
// passes in, checks DigestMultibase when present, and returns the fetched method
// to render.
func (m RenderMethod) Dereference(ctx context.Context, fetcher Fetcher) (RenderMethod, error) {
	if m.ID == "" {
		return RenderMethod{}, fmt.Errorf("renderMethod.id is required to dereference")
	}
	if fetcher == nil {
		return RenderMethod{}, fmt.Errorf("renderMethod.id %.64q needs a Fetcher", m.ID)
	}
	id, err := serializeURL(m.ID, "renderMethod.id")
	if err != nil {
		return RenderMethod{}, err
	}
	data, err := fetcher.Fetch(ctx, TemplateReference{ID: id, DigestMultibase: m.DigestMultibase})
	if err != nil {
		return RenderMethod{}, fmt.Errorf("fetch renderMethod.id: %w", err)
	}
	if m.DigestMultibase != "" {
		if err := verifyDigestMultibase(data, m.DigestMultibase); err != nil {
			return RenderMethod{}, fmt.Errorf("renderMethod.digestMultibase: %w", err)
		}
	}
	var fetched RenderMethod
	if err := json.Unmarshal(data, &fetched); err != nil {
		return RenderMethod{}, fmt.Errorf("decode fetched render method: %w", err)
	}
	if fetched.Type != m.Type || fetched.RenderSuite != m.RenderSuite {
		return RenderMethod{}, fmt.Errorf("fetched render method is %.64q/%.64q, want %.64q/%.64q", fetched.Type, fetched.RenderSuite, m.Type, m.RenderSuite)
	}
	if err := fetched.Validate(); err != nil {
		return RenderMethod{}, fmt.Errorf("fetched render method: %w", err)
	}
	return fetched, nil
}

// isSupportedRenderSuite reports whether this SDK renders suite.
func isSupportedRenderSuite(suite string) bool {
	switch suite {
	case "summary", "html", "static":
		return true
	default:
		return false
	}
}

// Template is the template member of a render method (WD-20261013 §2.2): a
// data: URL decoded into Embedded, or an object referencing an external
// template in Reference. Exactly one of the two is set.
//
// The SDK sets no size limit on templates. A decoded data: template is never
// larger than its encoded form in the credential, so the application bounds
// embedded templates by limiting the credential size it accepts, and bounds
// fetched templates in its Fetcher.
type Template struct {
	Embedded  *EmbeddedTemplate
	Reference *TemplateReference
}

// EmbeddedTemplate is a template carried in the credential as a data: URL,
// decoded into its media type and bytes. It is covered by the credential proof.
type EmbeddedTemplate struct {
	MediaType string
	Bytes     []byte
}

// TemplateReference points to a template outside the credential. WD-20261013
// §2.2 requires id, recommends mediaType and makes digestMultibase optional.
// ID follows the URL syntax; the Fetcher owns scheme and address
// policy. When DigestMultibase is set, the resolved bytes must match it.
type TemplateReference struct {
	ID              string `json:"id"`
	MediaType       string `json:"mediaType,omitempty"`
	DigestMultibase string `json:"digestMultibase,omitempty"`
}

// OutputPreference is the outputPreference member of a render method
// (WD-20261013 §2.2.2.3): the access modes, media type and style the issuer
// suggests for the rendered output.
type OutputPreference struct {
	AccessMode []string     `json:"accessMode,omitempty"`
	MediaType  string       `json:"mediaType,omitempty"`
	Style      *RenderStyle `json:"style,omitempty"`
}

// RenderStyle is the style member of an outputPreference (WD-20261013
// §2.2.2.3): CSS-compatible width and height preferences for the iframe.
type RenderStyle struct {
	Width  string `json:"width,omitempty"`
	Height string `json:"height,omitempty"`
}

// Validate checks a render method against WD-20261013 §2.2: required members,
// the render suite, template URLs and media types, outputPreference, and the
// content of an embedded template. A data: URL in template.id carries the
// template in the credential, so it is decoded and checked here too. An id or
// template.id longer than 8 KiB is refused, unless it is a data: URL with an
// opaque path, such as "data:<media type>,<data>". It does
// not fetch a referenced template; ValidateExternalTemplate checks one after
// retrieval.
//
// WD-20261013 §2.2 makes both id and template optional. This SDK also requires
// a supported suite to have at least one of them, because a method with neither
// cannot be rendered and a signed credential cannot be corrected.
func (m RenderMethod) Validate() error {
	if err := m.validateInCredential(); err != nil {
		return err
	}
	if m.Template == nil || m.Template.Reference == nil || !isSupportedRenderSuite(m.RenderSuite) {
		return nil
	}
	if _, ok := referencedDataURL(m.Template.Reference.ID); ok {
		// Signing is the last point where a broken data: template can be refused.
		_, _, err := templateBytes(context.Background(), m, nil)
		return err
	}
	return nil
}

// validateInCredential checks the render method's shape and an embedded
// template's content. The render entry points call it in place of Validate,
// because templateBytes then decodes and checks a referenced template once.
func (m RenderMethod) validateInCredential() error {
	if err := m.validateFormat(); err != nil {
		return err
	}
	if m.Template == nil {
		return nil
	}
	return m.validateTemplateContent()
}

// validateFormat checks the signed render method's shape without reading or
// fetching template content. Embedded content is checked by Validate before
// signing; referenced content is checked after retrieval.
func (m RenderMethod) validateFormat() error {
	if m.Type == "" {
		return fmt.Errorf("renderMethod.type is required")
	}
	if m.Type != "SuiteRenderMethod" {
		return fmt.Errorf("renderMethod.type must be SuiteRenderMethod")
	}
	if m.RenderSuite == "" {
		return fmt.Errorf("renderMethod.renderSuite is required")
	}
	if isSupportedRenderSuite(m.RenderSuite) && m.Template == nil && m.ID == "" {
		return fmt.Errorf("renderMethod requires template or id")
	}
	if m.ID != "" {
		if err := validateURL(m.ID, "renderMethod.id"); err != nil {
			return err
		}
	}
	if m.DigestMultibase != "" {
		if _, err := decodeDigestMultibase(m.DigestMultibase); err != nil {
			return fmt.Errorf("renderMethod.digestMultibase: %w", err)
		}
	}
	if m.Template != nil && m.Template.Reference != nil && m.Template.Reference.DigestMultibase != "" {
		if _, err := decodeDigestMultibase(m.Template.Reference.DigestMultibase); err != nil {
			return fmt.Errorf("renderMethod.template.digestMultibase: %w", err)
		}
	}
	for i, pointer := range m.RenderProperty {
		if err := validateJSONPointer(pointer); err != nil {
			return fmt.Errorf("renderMethod.renderProperty[%d]: %w", i, err)
		}
	}
	if m.Template != nil {
		if err := m.Template.validate(); err != nil {
			return fmt.Errorf("renderMethod.template: %w", err)
		}
	}
	if err := m.OutputPreference.validate(); err != nil {
		return fmt.Errorf("renderMethod.outputPreference: %w", err)
	}
	return nil
}

func (t *Template) validate() error {
	if t == nil || (t.Embedded == nil) == (t.Reference == nil) {
		return fmt.Errorf("exactly one of embedded or reference template must be set")
	}
	if t.Reference != nil {
		if t.Reference.ID == "" {
			return fmt.Errorf("template reference id is required")
		}
		if err := validateURL(t.Reference.ID, "template reference id"); err != nil {
			return err
		}
		if err := validateMediaType(t.Reference.MediaType); err != nil {
			return fmt.Errorf("template reference %w", err)
		}
	}
	if t.Embedded != nil {
		// A comma would end the media type early in the data: URL MarshalJSON writes.
		if err := validateMediaType(t.Embedded.MediaType); err != nil || strings.Contains(t.Embedded.MediaType, ",") {
			return fmt.Errorf("embedded template mediaType %.64q is not a valid media type", t.Embedded.MediaType)
		}
	}
	return nil
}

// validate checks outputPreference against WD-20261013 §2.2.2.3: accessMode lists
// one or more of auditory, tactile, textual and visual, and mediaType is a
// valid media type.
func (p *OutputPreference) validate() error {
	if p == nil {
		return nil
	}
	if p.AccessMode != nil && len(p.AccessMode) == 0 {
		return fmt.Errorf("accessMode must list at least one value")
	}
	for i, mode := range p.AccessMode {
		switch mode {
		case "auditory", "tactile", "textual", "visual":
		default:
			return fmt.Errorf("accessMode[%d] %.64q is not auditory, tactile, textual or visual", i, mode)
		}
	}
	return validateMediaType(p.MediaType)
}

// validateMediaType checks the syntax of an optional media type: empty is
// allowed, anything else must parse as type/subtype with optional parameters.
// mime.ParseMediaType also accepts a bare token such as "png" and wildcards such
// as "text/*", neither of which names a media type (RFC 6838 §4.2), so both are
// rejected here: the value is signed and cannot be corrected after issuance.
func validateMediaType(mediaType string) error {
	if mediaType == "" {
		return nil
	}
	parsed, _, err := mime.ParseMediaType(mediaType)
	if err != nil || !strings.Contains(parsed, "/") || strings.Contains(parsed, "*") {
		// The media type comes from the credential and has no size limit, so only its start is quoted.
		return fmt.Errorf("mediaType %.64q is not a valid media type", mediaType)
	}
	return nil
}

// maxURLBytes bounds a URL other than a data: URL that holds a template. The
// URL Standard sets no limit; the parser in use takes time quadratic in the
// length of a userinfo or host (1.2 s for a 195 KiB userinfo), and the id comes
// from the credential.
const maxURLBytes = 8 << 10

func validateURL(raw, field string) error {
	// The parser has no failure in an opaque path, a query or a fragment, so it
	// cannot refuse this URL; it would only cost about 35 ms per MiB of template.
	if holdsTemplate(raw) {
		return nil
	}
	_, err := parseURL(raw, field)
	return err
}

// holdsTemplate reports whether raw is a data: URL with an opaque path, the
// form "data:<media type>,<data>". "data://..." has an authority like any other
// URL.
func holdsTemplate(raw string) bool {
	dataURL, ok := referencedDataURL(raw)
	return ok && !strings.HasPrefix(dataURL[len("data:"):], "/")
}

// serializeURL returns raw as the URL Standard parser serializes it. A Fetcher
// gets this form, so it requests the URL that validateURL accepted:
// "https:example.org/t" is "https://example.org/t".
func serializeURL(raw, field string) (string, error) {
	parsed, err := parseURL(raw, field)
	if err != nil {
		return "", err
	}
	return parsed.Href(false), nil
}

func parseURL(raw, field string) (*whatwgurl.Url, error) {
	if len(raw) > maxURLBytes && !holdsTemplate(raw) {
		return nil, fmt.Errorf("%s is %d bytes; this SDK accepts at most %d for a URL, and more only for a data: URL of the form data:<media type>,<data>", field, len(raw), maxURLBytes)
	}
	parsed, err := whatwgurl.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%s must be a URL of the WHATWG URL Standard: %w", field, err)
	}
	return parsed, nil
}

func validateJSONPointer(pointer string) error {
	if pointer == "" {
		return nil
	}
	if !strings.HasPrefix(pointer, "/") {
		return fmt.Errorf("must be a valid RFC 6901 JSON Pointer")
	}
	for i := 0; i < len(pointer); i++ {
		if pointer[i] != '~' {
			continue
		}
		if i+1 >= len(pointer) || (pointer[i+1] != '0' && pointer[i+1] != '1') {
			return fmt.Errorf("must be a valid RFC 6901 JSON Pointer")
		}
		i++
	}
	return nil
}

func (t Template) MarshalJSON() ([]byte, error) {
	if err := t.validate(); err != nil {
		return nil, err
	}
	if t.Reference != nil {
		return json.Marshal(t.Reference)
	}
	// Whitespace is valid around media type parameters but not in a URL (RFC 3986).
	mediaType := strings.Join(strings.Fields(t.Embedded.MediaType), "")
	encoded := base64.StdEncoding.EncodeToString(t.Embedded.Bytes)
	return json.Marshal("data:" + mediaType + ";base64," + encoded)
}

func (t *Template) UnmarshalJSON(data []byte) error {
	var next Template
	if err := next.decodeJSON(data); err != nil {
		return err
	}
	if err := next.validate(); err != nil {
		return err
	}
	*t = next
	return nil
}

// isDataURL reports whether raw uses the data: scheme. URI schemes are
// case-insensitive (RFC 3986 §3.1), so "DATA:" is a data URL too.
func isDataURL(raw string) bool {
	return len(raw) >= 5 && strings.EqualFold(raw[:5], "data:")
}

// referencedDataURL reports whether id is a data: URL and returns it the way
// the URL Standard parser reads it: C0 controls and spaces around it, and tabs
// and newlines inside it, are removed before the scheme is read. A prefix test
// on the raw id would send " data:..." to the Fetcher. The parser is not
// called here: it takes about 35 ms per MiB, and a data: URL holds a template.
// It also reads a data: string in template, and tells whether renderMethod.id
// is bounded by maxURLBytes.
func referencedDataURL(id string) (string, bool) {
	id = strings.TrimFunc(id, func(r rune) bool { return r <= ' ' })
	if strings.ContainsAny(id, "\t\n\r") {
		id = strings.NewReplacer("\t", "", "\n", "", "\r", "").Replace(id)
	}
	return id, isDataURL(id)
}

// decodeDataURL decodes a data URL. RFC 2397 lets the media type be empty. Like
// the WHATWG Fetch data: URL processor, it matches ";base64" case-insensitively,
// percent-decodes, then decodes base64 with forgiving-base64.
func decodeDataURL(raw string) (*EmbeddedTemplate, error) {
	metadata, payload, ok := strings.Cut(raw[5:], ",")
	if !ok {
		return nil, fmt.Errorf("embedded template must use a valid data URL")
	}
	unescaped, err := url.PathUnescape(payload)
	if err != nil {
		return nil, fmt.Errorf("decode embedded template data URL: %w", err)
	}
	mediaType, decoded := metadata, []byte(unescaped)
	if n := len(metadata) - len(";base64"); n >= 0 && strings.EqualFold(metadata[n:], ";base64") {
		mediaType = metadata[:n]
		if decoded, err = forgivingBase64Decode(unescaped); err != nil {
			return nil, fmt.Errorf("decode embedded template data URL: %w", err)
		}
	}
	if mediaType == "" {
		mediaType = "text/plain;charset=US-ASCII"
	} else if strings.HasPrefix(mediaType, ";") {
		mediaType = "text/plain" + mediaType
	}
	return &EmbeddedTemplate{MediaType: mediaType, Bytes: decoded}, nil
}

// forgivingBase64Decode is forgiving-base64 decode (WHATWG Infra Standard), which
// Fetch uses for data: URLs: ASCII whitespace is removed and padding is
// optional, so a data: URL another issuer wrote without "=" still decodes.
func forgivingBase64Decode(encoded string) ([]byte, error) {
	encoded = strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' || r == '\f' || r == '\r' || r == ' ' {
			return -1
		}
		return r
	}, encoded)
	if len(encoded)%4 == 0 {
		encoded = strings.TrimSuffix(encoded, "=")
		encoded = strings.TrimSuffix(encoded, "=")
	}
	if len(encoded)%4 == 1 {
		return nil, fmt.Errorf("base64 data has a length of 1 modulo 4")
	}
	return base64.RawStdEncoding.DecodeString(encoded)
}

func (t *Template) decodeJSON(data []byte) error {
	var raw string
	if len(data) > 0 && data[0] == '"' {
		if err := json.Unmarshal(data, &raw); err != nil {
			return err
		}
		// One rule reads a data: URL, as a string here and as template.id.
		if dataURL, ok := referencedDataURL(raw); ok {
			embedded, err := decodeDataURL(dataURL)
			if err != nil {
				return err
			}
			t.Embedded = embedded
			return nil
		}
		t.Reference = &TemplateReference{ID: raw}
		return nil
	}
	var ref TemplateReference
	if err := json.Unmarshal(data, &ref); err != nil {
		return err
	}
	t.Reference = &ref
	return nil
}
