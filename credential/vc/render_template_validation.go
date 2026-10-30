package vc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

type TemplateFetcher interface {
	Fetch(context.Context, TemplateReference) ([]byte, error)
}

// RenderMethodFetcher retrieves a remote render method document.
type RenderMethodFetcher interface {
	FetchRenderMethod(context.Context, string) ([]byte, error)
}

func (m RenderMethod) validateTemplateContent() error {
	switch m.RenderSuite {
	case "summary":
		return m.validateSummaryTemplateContent()
	case "html":
		return m.validateHTMLTemplate()
	case "static":
		return m.validateStaticTemplate()
	default:
		return nil
	}
}

func (m RenderMethod) validateSummaryTemplateContent() error {
	if m.Template == nil || m.Template.Reference != nil {
		return nil
	}
	if m.Template.Embedded.MediaType != "application/json" {
		return fmt.Errorf("renderMethod.template media type for summary must be application/json")
	}
	var summary SummaryTemplate
	decoder := json.NewDecoder(strings.NewReader(string(m.Template.Embedded.Bytes)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&summary); err != nil {
		return fmt.Errorf("invalid summary template: %w", err)
	}
	if summary.Name == "" || summary.Description == "" || len(summary.Fields) == 0 {
		return fmt.Errorf("summary template requires name, description, and at least one field")
	}
	for i, field := range summary.Fields {
		if field.Label == "" {
			return fmt.Errorf("summary template fields[%d].label is required", i)
		}
		if field.Value == "" || validateJSONPointer(field.Value) != nil {
			return fmt.Errorf("summary template fields[%d].value must be a valid JSON Pointer", i)
		}
	}
	return nil
}

func (m RenderMethod) validateHTMLTemplate() error {
	if m.Template == nil || m.Template.Reference != nil {
		return nil
	}
	if m.Template.Embedded.MediaType != "text/html" {
		return fmt.Errorf("renderMethod.template media type for html must be text/html")
	}
	lower := strings.ToLower(string(m.Template.Embedded.Bytes))
	for _, tag := range []string{"<html", "<head", "<body"} {
		if strings.Contains(lower, tag) {
			return fmt.Errorf("html template must be a fragment without %s element", tag[:len(tag)-1])
		}
	}
	return nil
}

func (m RenderMethod) validateStaticTemplate() error {
	if m.Template == nil || m.Template.Reference != nil {
		return nil
	}
	if m.DeliveryMode == "" {
		return fmt.Errorf("static render method requires deliveryMode")
	}
	return nil
}

func (m RenderMethod) ValidateExternalTemplate(ctx context.Context, fetcher TemplateFetcher) error {
	if err := m.Validate(); err != nil {
		return err
	}
	if m.Template == nil || m.Template.Reference == nil {
		return nil
	}
	if fetcher == nil {
		return fmt.Errorf("template fetcher is required for external template validation")
	}
	ref := *m.Template.Reference
	data, err := fetcher.Fetch(ctx, ref)
	if err != nil {
		return fmt.Errorf("fetch external template: %w", err)
	}
	if ref.DigestMultibase != "" {
		if err := VerifyDigestMultibase(data, ref.DigestMultibase); err != nil {
			return fmt.Errorf("template digest verification failed: %w", err)
		}
	}
	copy := m
	copy.Template = &Template{Embedded: &EmbeddedTemplate{MediaType: ref.MediaType, Bytes: data}}
	if err := copy.Validate(); err != nil {
		return fmt.Errorf("external template validation: %w", err)
	}
	return nil
}

// ValidateExternalRenderMethod fetches and verifies a remote render method
// document identified by m.ID. The outer digest is required for this flow.
func (m RenderMethod) ValidateExternalRenderMethod(ctx context.Context, fetcher RenderMethodFetcher) error {
	if err := m.Validate(); err != nil {
		return err
	}
	if m.ID == "" {
		return fmt.Errorf("renderMethod.id is required for external render method validation")
	}
	if m.DigestMultibase == "" {
		return fmt.Errorf("renderMethod.digestMultibase is required for external render method validation")
	}
	if fetcher == nil {
		return fmt.Errorf("render method fetcher is required")
	}
	data, err := fetcher.FetchRenderMethod(ctx, m.ID)
	if err != nil {
		return fmt.Errorf("fetch external render method: %w", err)
	}
	if err := VerifyDigestMultibase(data, m.DigestMultibase); err != nil {
		return fmt.Errorf("render method digest verification failed: %w", err)
	}
	var fetched RenderMethod
	if err := json.Unmarshal(data, &fetched); err != nil {
		return fmt.Errorf("decode external render method: %w", err)
	}
	return fetched.Validate()
}

// VerifyDigestMultibase verifies a base64url multibase SHA-256 multihash.
func VerifyDigestMultibase(data []byte, encoded string) error {
	if !strings.HasPrefix(encoded, "u") {
		return fmt.Errorf("digest must use base64url-no-padding multibase")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(encoded, "u"))
	if err != nil || len(raw) != 34 || raw[0] != 0x12 || raw[1] != 0x20 {
		return fmt.Errorf("digest must contain a SHA-256 multihash")
	}
	hash := sha256.Sum256(data)
	if !bytes.Equal(raw[2:], hash[:]) {
		return fmt.Errorf("digest does not match template bytes")
	}
	return nil
}
