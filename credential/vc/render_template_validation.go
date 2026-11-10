package vc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"mime"
	"strings"
)

// Fetcher retrieves the template a credential references. ref.ID comes
// from the credential, so the implementation owns the scheme and address policy,
// the read limit, the timeout, and the comparison with ref.MediaType.
type Fetcher interface {
	Fetch(context.Context, TemplateReference) ([]byte, error)
}

func (m RenderMethod) validateTemplateContent() error {
	switch m.RenderSuite {
	case "summary":
		return m.validateSummaryTemplateContent()
	case "html":
		return m.validateHTMLTemplate()
	case "static":
		// deliveryMode is optional in the W3C TR, and static payload bytes are
		// opaque to the SDK, so there are no static content rules to apply.
		return nil
	default:
		return nil
	}
}

// isMediaType reports whether got names the media type want, comparing after
// parsing. Type and subtype are compared case-insensitively (RFC 6838 §4.2); this
// SDK ignores parameters by its own choice: "Application/JSON; charset=utf-8" is
// application/json.
func isMediaType(got, want string) bool {
	parsed, _, err := mime.ParseMediaType(got)
	return err == nil && parsed == want
}

func (m RenderMethod) validateSummaryTemplateContent() error {
	if m.Template == nil || m.Template.Reference != nil {
		return nil
	}
	if !isMediaType(m.Template.Embedded.MediaType, "application/json") {
		return fmt.Errorf("renderMethod.template media type for summary must be application/json")
	}
	var summary SummaryTemplate
	decoder := json.NewDecoder(strings.NewReader(string(m.Template.Embedded.Bytes)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&summary); err != nil {
		return fmt.Errorf("invalid summary template: %w", err)
	}
	if err := requireSummaryMembers(m.Template.Embedded.Bytes); err != nil {
		return fmt.Errorf("summary template: %w", err)
	}
	for i, field := range summary.Fields {
		if strings.HasPrefix(field.Label, "/") {
			return fmt.Errorf("summary template fields[%d].label must be a literal string", i)
		}
		if field.Value == "" || validateJSONPointer(field.Value) != nil {
			return fmt.Errorf("summary template fields[%d].value must be a valid JSON Pointer", i)
		}
	}
	return nil
}

// requireSummaryMembers checks that the members the W3C summary object marks
// REQUIRED are present: name, description, fields, and each field's label and
// value. REQUIRED means present and not null; an empty string or an empty
// fields array is allowed. Decoding into SummaryTemplate alone cannot tell an
// absent member from an empty one, so the raw JSON is inspected.
func requireSummaryMembers(data []byte) error {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(data, &members); err != nil {
		return fmt.Errorf("decode summary object: %w", err)
	}
	for _, key := range []string{"name", "description", "fields"} {
		if !jsonMemberPresent(members[key]) {
			return fmt.Errorf("%s is required", key)
		}
	}
	var fields []map[string]json.RawMessage
	if err := json.Unmarshal(members["fields"], &fields); err != nil {
		return fmt.Errorf("fields must be an array of objects: %w", err)
	}
	for i, field := range fields {
		for _, key := range []string{"label", "value"} {
			if !jsonMemberPresent(field[key]) {
				return fmt.Errorf("fields[%d].%s is required", i, key)
			}
		}
	}
	return nil
}

func jsonMemberPresent(value json.RawMessage) bool {
	trimmed := bytes.TrimSpace(value)
	return len(trimmed) > 0 && !bytes.Equal(trimmed, []byte("null"))
}

func (m RenderMethod) validateHTMLTemplate() error {
	if m.Template == nil || m.Template.Reference != nil {
		return nil
	}
	if !isMediaType(m.Template.Embedded.MediaType, "text/html") {
		return fmt.Errorf("renderMethod.template media type for html must be text/html")
	}
	for _, tag := range []string{"html", "head", "body"} {
		if containsHTMLElement(string(m.Template.Embedded.Bytes), tag) {
			return fmt.Errorf("html template must be a fragment without <%s> element", tag)
		}
	}
	return nil
}

func containsHTMLElement(source, element string) bool {
	lower := strings.ToLower(source)
	needle := "<" + element
	for offset := 0; offset < len(lower); {
		index := strings.Index(lower[offset:], needle)
		if index < 0 {
			return false
		}
		index += offset + len(needle)
		if index == len(lower) {
			return true
		}
		switch lower[index] {
		case '>', '/', ' ', '\t', '\n', '\r', '\f':
			return true
		}
		offset = index
	}
	return false
}

func (m RenderMethod) ValidateExternalTemplate(ctx context.Context, fetcher Fetcher) error {
	if err := m.Validate(); err != nil {
		return err
	}
	if m.Template == nil || m.Template.Reference == nil {
		return nil
	}
	// templateBytes owns fetch, digest and content checks, so validation and
	// rendering accept exactly the same templates.
	_, err := templateBytes(ctx, m, fetcher)
	return err
}

// validateFetchedTemplate applies the content rules for embedded templates to
// bytes retrieved for a template reference. When the reference omits
// mediaType, the suite's expected media type is assumed so the content checks
// still run; a mediaType that is present must match as it does for embedded
// templates.
func (m RenderMethod) validateFetchedTemplate(ref TemplateReference, data []byte) error {
	mediaType := ref.MediaType
	if mediaType == "" {
		mediaType = defaultTemplateMediaType(m.RenderSuite)
	}
	fetched := m
	fetched.Template = &Template{Embedded: &EmbeddedTemplate{MediaType: mediaType, Bytes: data}}
	return fetched.validateTemplateContent()
}

func defaultTemplateMediaType(suite string) string {
	switch suite {
	case "summary":
		return "application/json"
	case "html":
		return "text/html"
	default:
		return ""
	}
}

// verifyDigestMultibase verifies a base64url multibase SHA-256 multihash.
func verifyDigestMultibase(data []byte, encoded string) error {
	expected, err := decodeDigestMultibase(encoded)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(data)
	if !bytes.Equal(expected, hash[:]) {
		return fmt.Errorf("digest does not match template bytes")
	}
	return nil
}

// decodeDigestMultibase checks the digestMultibase syntax the W3C TR
// requires -- multibase "u" (base64url-nopad) wrapping a SHA-2-256 multihash
// (0x12, length 0x20) -- and returns the 32-byte hash.
func decodeDigestMultibase(encoded string) ([]byte, error) {
	if !strings.HasPrefix(encoded, "u") {
		return nil, fmt.Errorf("digest must use base64url-no-padding multibase (\"u\" prefix)")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(encoded, "u"))
	if err != nil || len(raw) != 34 || raw[0] != 0x12 || raw[1] != 0x20 {
		return nil, fmt.Errorf("digest must contain a SHA-256 multihash")
	}
	return raw[2:], nil
}
