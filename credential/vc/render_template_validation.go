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

	"golang.org/x/net/html"
)

// Fetcher retrieves the template or render method a credential references.
// ref.ID is the id in the credential as the URL Standard parser serializes it,
// so a check on its host sees the host that net/http dials. net/http still
// refuses some URLs the URL Standard accepts, such as a "%" that starts no
// escape, and Fetch then fails. The implementation owns the scheme and
// address policy, the read limit, the timeout, and the comparison with
// ref.MediaType. The credential signature does not cover bytes fetched with an
// empty ref.DigestMultibase: refuse them here unless the issuer is trusted.
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
// parsing. Type and subtype are compared case-insensitively (RFC 9110 §8.3.1);
// this SDK ignores parameters by its own choice, so a malformed parameter does
// not stop a match: "Application/JSON; charset" is application/json.
func isMediaType(got, want string) bool {
	gotType, gotOK := mediaTypeName(got)
	wantType, wantOK := mediaTypeName(want)
	return gotOK && wantOK && gotType == wantType
}

// mediaTypeName returns the lower-cased type/subtype of a media type and drops
// its parameters, which this SDK does not compare.
func mediaTypeName(mediaType string) (string, bool) {
	name, _, _ := strings.Cut(mediaType, ";")
	parsed, _, err := mime.ParseMediaType(name)
	return parsed, err == nil
}

func (m RenderMethod) validateSummaryTemplateContent() error {
	if m.Template == nil || m.Template.Reference != nil {
		return nil
	}
	if !isMediaType(m.Template.Embedded.MediaType, "application/json") {
		return fmt.Errorf("renderMethod.template media type for summary must be application/json")
	}
	var summary SummaryTemplate
	if err := decodeExactMembers(m.Template.Embedded.Bytes, &summary, true); err != nil {
		// The decoder names an unknown member in full, and the template comes from the credential.
		return fmt.Errorf("invalid summary template: %w", boundedError{err})
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
	if tag, ok := findDocumentTag(m.Template.Embedded.Bytes); ok {
		return fmt.Errorf("html template must be a fragment without <%s> or </%s> tags", tag, tag)
	}
	return nil
}

// findDocumentTag returns the first html, head or body tag, start or end, in an
// HTML fragment. The payload code MUST NOT include these tags because the
// wrapper code provides them (VC Render Method, html suite). A tokenizer is
// used so that text in script, style, comments and attribute values, which
// holds no tags, is not mistaken for one.
func findDocumentTag(fragment []byte) (string, bool) {
	tokenizer := html.NewTokenizer(bytes.NewReader(fragment))
	for {
		switch tokenizer.Next() {
		case html.ErrorToken:
			// io.EOF ends the fragment; the reader is in memory, so no other error.
			return "", false
		case html.StartTagToken, html.EndTagToken, html.SelfClosingTagToken:
			name, _ := tokenizer.TagName()
			switch tag := string(name); tag {
			case "html", "head", "body":
				return tag, true
			}
		}
	}
}

func (m RenderMethod) ValidateExternalTemplate(ctx context.Context, fetcher Fetcher) error {
	if err := m.validateInCredential(); err != nil {
		return err
	}
	if m.Template == nil || m.Template.Reference == nil {
		return nil
	}
	// templateBytes owns fetch, digest and content checks, so validation and
	// rendering accept exactly the same templates.
	_, _, err := templateBytes(ctx, m, fetcher)
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
	// Strict refuses non-zero pad bits; it still skips CR and LF, which RFC 4648
	// §3.3 does not allow inside base64url, so they are refused first.
	if strings.ContainsAny(encoded, "\r\n") {
		return nil, fmt.Errorf("digest must use base64url-no-padding multibase without line breaks")
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(strings.TrimPrefix(encoded, "u"))
	if err != nil {
		return nil, fmt.Errorf("digest must use base64url-no-padding multibase: %w", err)
	}
	if len(raw) != 34 || raw[0] != 0x12 || raw[1] != 0x20 {
		return nil, fmt.Errorf("digest must contain a SHA-256 multihash")
	}
	return raw[2:], nil
}
