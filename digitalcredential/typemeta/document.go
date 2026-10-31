// A Type Metadata document as the publisher writes it: draft-ietf-oauth-sd-jwt-vc-19
// §5.2 (document), §5.5 (display), §5.6 (claims).

package typemeta

import (
	"encoding/json"
	"fmt"
	"slices"
)

// Document is one Type Metadata document (§5.2), for a publisher to build
// and Encode. It holds only the properties draft 19 defines; for extension
// properties see ParseEncoded. Fields left empty are not written.
type Document struct {
	VCT              string    `json:"vct"`
	Name             string    `json:"name,omitempty"`
	Description      string    `json:"description,omitempty"`
	Extends          string    `json:"extends,omitempty"`
	ExtendsIntegrity string    `json:"extends#integrity,omitempty"`
	Display          []Display `json:"display,omitempty"`
	Claims           []Claim   `json:"claims,omitempty"`
}

// Display is the display metadata of a type for one locale (§5.5).
type Display struct {
	Locale      string     `json:"locale,omitempty"` // RFC 5646 language tag, required
	Name        string     `json:"name,omitempty"`   // for end users, required
	Description string     `json:"description,omitempty"`
	Rendering   *Rendering `json:"rendering,omitempty"`
}

// Rendering holds the rendering methods draft 19 defines (§5.5.1); a method
// the SDK does not know is ignored when read.
type Rendering struct {
	Simple       *SimpleRendering `json:"simple,omitempty"`
	SVGTemplates []SVGTemplate    `json:"svg_templates,omitempty"`
}

// SimpleRendering is the "simple" rendering method (§5.5.1.1). Colors are
// RGB values of CSS Color Level 3 §4.2.1, such as "#12107c" or
// "rgb(18, 16, 124)".
type SimpleRendering struct {
	Logo            *Image `json:"logo,omitempty"`
	BackgroundImage *Image `json:"background_image,omitempty"`
	BackgroundColor string `json:"background_color,omitempty"`
	TextColor       string `json:"text_color,omitempty"`
}

// Image is a logo or a background image (§5.5.1.1.1, §5.5.1.1.2). URI is an
// https URL or a data: URI (§5.5.1). Of a data: URI, only the comma RFC 2397
// §3 requires is checked: the application that decodes it meets a bad
// mediatype or base64 there. URIIntegrity is nil when uri#integrity
// is absent; when set, even to "", the application that fetches URI passes
// it to CheckIntegrity, which refuses an empty value (§6). AltText is for the
// logo only (§5.5.1.1.1); it is not read for a background image.
type Image struct {
	URI          string  `json:"uri,omitempty"`
	URIIntegrity *string `json:"uri#integrity,omitempty"`
	AltText      string  `json:"alt_text,omitempty"`
}

// SVGTemplate is one SVG template (§5.5.1.2). URI and URIIntegrity are
// read as for Image. Properties is required when a type has more than one template.
type SVGTemplate struct {
	URI          string         `json:"uri,omitempty"`
	URIIntegrity *string        `json:"uri#integrity,omitempty"`
	Properties   *SVGProperties `json:"properties,omitempty"`
}

// SVGProperties tells what an SVG template is made for (§5.5.1.2.1); at
// least one is set. Orientation is "portrait" or "landscape", ColorScheme
// "light" or "dark", Contrast "normal" or "high".
type SVGProperties struct {
	Orientation string `json:"orientation,omitempty"`
	ColorScheme string `json:"color_scheme,omitempty"`
	Contrast    string `json:"contrast,omitempty"`
}

// Claim is the metadata of the claim or claims Path selects (§5.6). A Path
// element is a string (an object key), nil (every element of an array) or a
// non-negative int (an array index), counted on the payload as issued
// (§5.6.1). SD is "always", "allowed" or "never" (§5.6.4); SVGID names the
// claim in SVG templates (§5.5.1.2.2).
type Claim struct {
	Path      []any          `json:"path"`
	Display   []ClaimDisplay `json:"display,omitempty"`
	Mandatory bool           `json:"mandatory,omitempty"`
	SD        string         `json:"sd,omitempty"`
	SVGID     string         `json:"svg_id,omitempty"`
}

// ClaimDisplay is the display metadata of a claim for one locale (§5.6.2).
type ClaimDisplay struct {
	Locale      string `json:"locale,omitempty"` // RFC 5646 language tag, required
	Label       string `json:"label,omitempty"`  // for end users, required
	Description string `json:"description,omitempty"`
}

// Encoded is a Type Metadata document that passed the checks of Encode or
// ParseEncoded, with the bytes the publisher serves.
type Encoded struct {
	vct   string
	bytes []byte
}

// VCT is the vct of the document.
func (e *Encoded) VCT() string {
	if e == nil {
		return ""
	}
	return e.vct
}

// Bytes returns a copy of the document's bytes, to serve unchanged: the
// integrity of every reference to it is over exactly these bytes (§6).
func (e *Encoded) Bytes() []byte {
	if e == nil {
		return nil
	}
	return slices.Clone(e.bytes)
}

// Integrity is Integrity(Bytes()): the value an issuer writes as
// vct#integrity, and a child document as extends#integrity.
func (e *Encoded) Integrity() string {
	if e == nil {
		return ""
	}
	return Integrity(e.bytes)
}

// Encode checks d by the rules Load applies to one document (§5.2, §5.5,
// §5.6), with a non-empty VCT, no svg_id used twice and no ExtendsIntegrity
// without Extends, then encodes it once with encoding/json. It does not
// follow Extends, which needs the parent document. Errors wrap ErrInvalid or
// ErrClaims as Load's do; a document over 256 KiB is ErrInvalid. Encoding
// one Document twice gives the same bytes, and the result shares nothing
// with d.
func (d Document) Encode() (*Encoded, error) {
	b, err := json.Marshal(d)
	if err != nil {
		return nil, fmt.Errorf("%w: typemeta: Encode: %v", ErrInvalid, err)
	}
	return parseEncoded(b)
}

// ParseEncoded checks doc, a Type Metadata document written as JSON, by the
// rules of Encode and keeps a copy of its exact bytes, so a document with
// extension properties (§5.2) keeps them. A publisher adding extension
// properties at the top level can embed Document in its own struct and
// json.Marshal that. Name them with a prefix of your own, so they cannot
// clash with properties a later draft defines (draft 20 adds dir to
// display). Properties the SDK does not understand are ignored, never read.
func ParseEncoded(doc []byte) (*Encoded, error) {
	return parseEncoded(slices.Clone(doc))
}

// parseEncoded checks b, which it keeps.
func parseEncoded(b []byte) (*Encoded, error) {
	d, err := readDocument(b)
	if err != nil {
		return nil, err
	}
	if d.vct == "" {
		return nil, fmt.Errorf("%w: typemeta: vct is empty; it names the type the document describes (draft-ietf-oauth-sd-jwt-vc-19 §5.2)", ErrInvalid)
	}
	if !d.hasExtends && d.hasExtendsIntegrity {
		return nil, fmt.Errorf("%w: typemeta: extends#integrity without extends (draft-ietf-oauth-sd-jwt-vc-19 §6)", ErrInvalid)
	}
	claims, err := d.readClaims()
	if err != nil {
		return nil, err
	}
	if err := checkSVGIDs(claims); err != nil {
		return nil, err
	}
	return &Encoded{vct: d.vct, bytes: b}, nil
}

func (d Display) clone() Display {
	if d.Rendering != nil {
		r := *d.Rendering
		if r.Simple != nil {
			s := *r.Simple
			if s.Logo != nil {
				l := *s.Logo
				l.URIIntegrity = cloneString(l.URIIntegrity)
				s.Logo = &l
			}
			if s.BackgroundImage != nil {
				b := *s.BackgroundImage
				b.URIIntegrity = cloneString(b.URIIntegrity)
				s.BackgroundImage = &b
			}
			r.Simple = &s
		}
		if r.SVGTemplates != nil {
			r.SVGTemplates = slices.Clone(r.SVGTemplates)
			for i, t := range r.SVGTemplates {
				r.SVGTemplates[i].URIIntegrity = cloneString(t.URIIntegrity)
				if t.Properties != nil {
					p := *t.Properties
					r.SVGTemplates[i].Properties = &p
				}
			}
		}
		d.Rendering = &r
	}
	return d
}

func (c Claim) clone() Claim {
	c.Path = slices.Clone(c.Path)
	c.Display = slices.Clone(c.Display)
	return c
}

func cloneString(p *string) *string {
	if p == nil {
		return nil
	}
	s := *p
	return &s
}
