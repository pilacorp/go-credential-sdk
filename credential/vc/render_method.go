package vc

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// RenderMethod represents a W3C SuiteRenderMethod entry.
type RenderMethod struct {
	ID               string            `json:"id,omitempty"`
	Type             string            `json:"type"`
	RenderSuite      string            `json:"renderSuite"`
	Name             string            `json:"name,omitempty"`
	Description      string            `json:"description,omitempty"`
	RenderProperty   []string          `json:"renderProperty,omitempty"`
	Template         *Template         `json:"template,omitempty"`
	DigestMultibase  string            `json:"digestMultibase,omitempty"`
	OutputPreference *OutputPreference `json:"outputPreference,omitempty"`
	DeliveryMode     string            `json:"deliveryMode,omitempty"`
}

type Template struct {
	Embedded  *EmbeddedTemplate
	Reference *TemplateReference
}

type EmbeddedTemplate struct {
	MediaType string
	Bytes     []byte
}

type TemplateReference struct {
	ID              string `json:"id"`
	MediaType       string `json:"mediaType,omitempty"`
	DigestMultibase string `json:"digestMultibase,omitempty"`
}

type OutputPreference struct {
	AccessMode []string     `json:"accessMode,omitempty"`
	MediaType  string       `json:"mediaType,omitempty"`
	Style      *RenderStyle `json:"style,omitempty"`
}

type RenderStyle struct {
	Width  string `json:"width,omitempty"`
	Height string `json:"height,omitempty"`
}

func (m RenderMethod) Validate() error {
	if m.Type == "" {
		return fmt.Errorf("renderMethod.type is required")
	}
	if m.Type != "SuiteRenderMethod" {
		return fmt.Errorf("renderMethod.type must be SuiteRenderMethod")
	}
	if m.RenderSuite == "" {
		return fmt.Errorf("renderMethod.renderSuite is required")
	}
	if m.ID != "" {
		if err := validateURL(m.ID, "renderMethod.id"); err != nil {
			return err
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
		if err := m.validateTemplateContent(); err != nil {
			return err
		}
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
	}
	return nil
}

func validateURL(raw, field string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || ((parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Host == "") {
		return fmt.Errorf("%s must be a valid URL", field)
	}
	return nil
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
	mediaType := t.Embedded.MediaType
	encoded := base64.StdEncoding.EncodeToString(t.Embedded.Bytes)
	return json.Marshal("data:" + mediaType + ";base64," + encoded)
}

func (t *Template) UnmarshalJSON(data []byte) error {
	var raw string
	if len(data) > 0 && data[0] == '"' {
		if err := json.Unmarshal(data, &raw); err != nil {
			return err
		}
		if strings.HasPrefix(raw, "data:") {
			parts := strings.SplitN(strings.TrimPrefix(raw, "data:"), ",", 2)
			if len(parts) != 2 || !strings.HasSuffix(parts[0], ";base64") {
				return fmt.Errorf("embedded template must use a base64 data URL")
			}
			mediaType := strings.TrimSuffix(parts[0], ";base64")
			payload := parts[1]
			decoded, err := base64.StdEncoding.DecodeString(payload)
			if err != nil {
				return fmt.Errorf("decode embedded template: %w", err)
			}
			t.Embedded = &EmbeddedTemplate{MediaType: mediaType, Bytes: decoded}
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
