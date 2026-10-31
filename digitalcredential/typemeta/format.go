// Reading one Type Metadata document: draft-ietf-oauth-sd-jwt-vc-19 §5.2
// (format), §5.5 and §5.5.1 (display, rendering), §5.6 and §5.6.1-§5.6.4
// (claims). Load, Encode and ParseEncoded share these rules. Properties the
// SDK does not understand are ignored (§5.2).

package typemeta

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/pilacorp/go-credential-sdk/digitalcredential/internal/jsonint"
	"github.com/pilacorp/go-credential-sdk/digitalcredential/internal/safehttp"
	"github.com/pilacorp/go-credential-sdk/jose"
)

// document is one document after the checks of §5.2 and §5.5; its claims
// are read apart, in phase two of Load.
type document struct {
	vct, name, description string
	extends                string
	extendsIntegrity       string
	hasExtends             bool
	hasExtendsIntegrity    bool
	display                []Display
	hasDisplay             bool
	claims                 any // the raw claims value, read in phase two
	hasClaims              bool
}

// claimMeta is a Claim with which properties its document sets, so a child
// overrides only those (§5.6.5).
type claimMeta struct {
	Claim
	hasDisplay, hasMandatory, hasSD, hasSVGID bool
}

// readDocument reads raw as one Type Metadata document. Its errors wrap
// ErrInvalid; they name the property at fault and quote none of its value.
func readDocument(raw []byte) (*document, error) {
	if len(raw) > maxDocumentBytes {
		return nil, invalid("the document is over %d bytes, the SDK's limit", maxDocumentBytes)
	}
	v, err := jose.DecodeJSON(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: typemeta: %w", ErrInvalid, err)
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, invalid("the document is not a JSON object (draft-ietf-oauth-sd-jwt-vc-19 §5.2)")
	}
	d := &document{}
	if d.vct, ok = obj["vct"].(string); !ok {
		return nil, invalid("vct is absent or not a string (draft-ietf-oauth-sd-jwt-vc-19 §5.2)")
	}
	if !optString(obj, "name", &d.name) || !optString(obj, "description", &d.description) {
		return nil, invalid("name or description is not a string (draft-ietf-oauth-sd-jwt-vc-19 §5.2)")
	}
	if _, d.hasExtends = obj["extends"]; d.hasExtends {
		if d.extends, _ = obj["extends"].(string); d.extends == "" {
			return nil, invalid("extends is not a non-empty string; it names the type extended (draft-ietf-oauth-sd-jwt-vc-19 §5.4)")
		}
	}
	_, d.hasExtendsIntegrity = obj["extends#integrity"]
	if !optString(obj, "extends#integrity", &d.extendsIntegrity) {
		return nil, invalid("extends#integrity is not a string (draft-ietf-oauth-sd-jwt-vc-19 §6)")
	}
	if d.hasExtendsIntegrity && d.extendsIntegrity == "" {
		return nil, invalid("extends#integrity is present and empty, so no hash can check the parent document; write typemeta.Integrity of it or leave it out (draft-ietf-oauth-sd-jwt-vc-19 §6)")
	}
	if v, ok := obj["display"]; ok {
		d.hasDisplay = true
		if d.display, err = readDisplays(v); err != nil {
			return nil, err
		}
	}
	d.claims, d.hasClaims = obj["claims"]
	return d, nil
}

func readDisplays(v any) ([]Display, error) {
	arr, ok := v.([]any)
	if !ok {
		return nil, invalid("display is not an array (draft-ietf-oauth-sd-jwt-vc-19 §5.5)")
	}
	if len(arr) > maxDisplay {
		return nil, invalid("display has over %d elements, the SDK's limit", maxDisplay)
	}
	out := make([]Display, len(arr))
	for i, e := range arr {
		m, ok := e.(map[string]any)
		if !ok {
			return nil, invalid("display[%d] is not an object (draft-ietf-oauth-sd-jwt-vc-19 §5.5)", i)
		}
		at := fmt.Sprintf("display[%d]", i)
		d := &out[i]
		if d.Locale, ok = m["locale"].(string); !ok || !wellFormedLangTag(d.Locale) {
			return nil, invalid("%s.locale is absent or not a well-formed language tag (draft-ietf-oauth-sd-jwt-vc-19 §5.5; RFC 5646 §2.1)", at)
		}
		if d.Name, ok = m["name"].(string); !ok {
			return nil, invalid("%s.name is absent or not a string (draft-ietf-oauth-sd-jwt-vc-19 §5.5)", at)
		}
		if !optString(m, "description", &d.Description) {
			return nil, invalid("%s.description is not a string (draft-ietf-oauth-sd-jwt-vc-19 §5.5)", at)
		}
		if r, ok := m["rendering"]; ok {
			var err error
			if d.Rendering, err = readRendering(r, at+".rendering"); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

// readRendering reads the two rendering methods of §5.5.1; any other
// method is ignored.
func readRendering(v any, at string) (*Rendering, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, invalid("%s is not an object (draft-ietf-oauth-sd-jwt-vc-19 §5.5.1)", at)
	}
	r := &Rendering{}
	if s, ok := m["simple"]; ok {
		sm, ok := s.(map[string]any)
		if !ok {
			return nil, invalid("%s.simple is not an object (draft-ietf-oauth-sd-jwt-vc-19 §5.5.1.1)", at)
		}
		r.Simple = &SimpleRendering{}
		var err error
		if r.Simple.Logo, err = readImage(sm, "logo", at+".simple"); err != nil {
			return nil, err
		}
		if r.Simple.BackgroundImage, err = readImage(sm, "background_image", at+".simple"); err != nil {
			return nil, err
		}
		for _, c := range []struct {
			name string
			dst  *string
		}{{"background_color", &r.Simple.BackgroundColor}, {"text_color", &r.Simple.TextColor}} {
			if _, ok := sm[c.name]; ok && (!optString(sm, c.name, c.dst) || !rgbColor(*c.dst)) {
				return nil, invalid("%s.simple.%s is not an RGB color value (draft-ietf-oauth-sd-jwt-vc-19 §5.5.1.1; CSS Color Level 3 §4.2.1)", at, c.name)
			}
		}
	}
	if s, ok := m["svg_templates"]; ok {
		arr, ok := s.([]any)
		if !ok {
			return nil, invalid("%s.svg_templates is not an array (draft-ietf-oauth-sd-jwt-vc-19 §5.5.1.2)", at)
		}
		r.SVGTemplates = make([]SVGTemplate, len(arr))
		for i, e := range arr {
			t, err := readSVGTemplate(e, len(arr) > 1, fmt.Sprintf("%s.svg_templates[%d]", at, i))
			if err != nil {
				return nil, err
			}
			r.SVGTemplates[i] = t
		}
	}
	return r, nil
}

func readImage(m map[string]any, name, at string) (*Image, error) {
	v, ok := m[name]
	if !ok {
		return nil, nil
	}
	at += "." + name
	im, ok := v.(map[string]any)
	if !ok {
		return nil, invalid("%s is not an object (draft-ietf-oauth-sd-jwt-vc-19 §5.5.1.1)", at)
	}
	img := &Image{}
	var err error
	if img.URI, err = readURI(im, at); err != nil {
		return nil, err
	}
	// §5.5.1.1.1 gives the logo alt_text; §5.5.1.1.2 gives background_image
	// only uri and uri#integrity, so its alt_text is an unknown property.
	section := "§5.5.1.1.2"
	if name == "logo" {
		section = "§5.5.1.1.1"
		if !optString(im, "alt_text", &img.AltText) {
			return nil, invalid("%s.alt_text is not a string (draft-ietf-oauth-sd-jwt-vc-19 %s)", at, section)
		}
	}
	if !optStringPtr(im, "uri#integrity", &img.URIIntegrity) {
		return nil, invalid("%s.uri#integrity is not a string (draft-ietf-oauth-sd-jwt-vc-19 %s)", at, section)
	}
	return img, nil
}

func readSVGTemplate(v any, several bool, at string) (SVGTemplate, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return SVGTemplate{}, invalid("%s is not an object (draft-ietf-oauth-sd-jwt-vc-19 §5.5.1.2)", at)
	}
	var t SVGTemplate
	var err error
	if t.URI, err = readURI(m, at); err != nil {
		return SVGTemplate{}, err
	}
	if !optStringPtr(m, "uri#integrity", &t.URIIntegrity) {
		return SVGTemplate{}, invalid("%s.uri#integrity is not a string (draft-ietf-oauth-sd-jwt-vc-19 §5.5.1.2)", at)
	}
	p, ok := m["properties"]
	if !ok {
		if several {
			return SVGTemplate{}, invalid("%s has no properties, which draft-ietf-oauth-sd-jwt-vc-19 §5.5.1.2 requires when there is more than one template", at)
		}
		return t, nil
	}
	pm, ok := p.(map[string]any)
	if !ok {
		return SVGTemplate{}, invalid("%s.properties is not an object (draft-ietf-oauth-sd-jwt-vc-19 §5.5.1.2.1)", at)
	}
	t.Properties = &SVGProperties{}
	// The values §5.5.1.2.1 defines for each property.
	for _, p := range []struct {
		name string
		vals [2]string
		dst  *string
	}{
		{"orientation", [2]string{"portrait", "landscape"}, &t.Properties.Orientation},
		{"color_scheme", [2]string{"light", "dark"}, &t.Properties.ColorScheme},
		{"contrast", [2]string{"normal", "high"}, &t.Properties.Contrast},
	} {
		v, ok := pm[p.name]
		if !ok {
			continue
		}
		if s, _ := v.(string); s != p.vals[0] && s != p.vals[1] {
			return SVGTemplate{}, invalid("%s.properties.%s is neither %s nor %s (draft-ietf-oauth-sd-jwt-vc-19 §5.5.1.2.1)", at, p.name, p.vals[0], p.vals[1])
		}
		*p.dst = v.(string)
	}
	if *t.Properties == (SVGProperties{}) {
		return SVGTemplate{}, invalid("%s.properties has none of orientation, color_scheme and contrast; draft-ietf-oauth-sd-jwt-vc-19 §5.5.1.2.1 requires one", at)
	}
	return t, nil
}

// readURI reads the uri of a rendering resource: an https URL with a host
// and no userinfo, or a data: URI (§5.5.1; RFC 2397 §3).
func readURI(m map[string]any, at string) (string, error) {
	s, ok := m["uri"].(string)
	if !ok {
		return "", invalid("%s.uri is absent or not a string (draft-ietf-oauth-sd-jwt-vc-19 §5.5.1)", at)
	}
	u, err := url.Parse(s)
	switch {
	case err != nil:
	case safehttp.HTTPSURL(u):
		return s, nil
	// RFC 2397 §3: data:[<mediatype>][;base64],<data>; the comma is
	// required.
	case u.Scheme == "data" && strings.Contains(u.Opaque, ","):
		return s, nil
	}
	return "", invalid("%s.uri is neither an https URL with a host nor a data: URI (draft-ietf-oauth-sd-jwt-vc-19 §5.5.1)", at)
}

// readClaims reads the claims property of d (§5.6), nil when absent. Its
// errors wrap ErrClaims: claim metadata processing fails (§5.6).
func (d *document) readClaims() ([]claimMeta, error) {
	if !d.hasClaims {
		return nil, nil
	}
	if d.claims == nil {
		return nil, claimsErr("claims is null; it is an array of claim metadata, or left out (draft-ietf-oauth-sd-jwt-vc-19 §5.6)")
	}
	arr, ok := d.claims.([]any)
	if !ok {
		return nil, claimsErr("claims is not an array (draft-ietf-oauth-sd-jwt-vc-19 §5.6)")
	}
	if len(arr) > maxClaims {
		return nil, claimsErr("claims has over %d elements, the SDK's limit", maxClaims)
	}
	out := make([]claimMeta, len(arr))
	for i, e := range arr {
		c, err := readClaim(e, fmt.Sprintf("claims[%d]", i))
		if err != nil {
			return nil, err
		}
		out[i] = c
	}
	return out, nil
}

func readClaim(v any, at string) (claimMeta, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return claimMeta{}, claimsErr("%s is not an object (draft-ietf-oauth-sd-jwt-vc-19 §5.6)", at)
	}
	var c claimMeta
	path, ok := m["path"].([]any)
	if !ok || len(path) == 0 {
		return claimMeta{}, claimsErr("%s.path is absent or not a non-empty array (draft-ietf-oauth-sd-jwt-vc-19 §5.6.1)", at)
	}
	if len(path) > maxPath {
		return claimMeta{}, claimsErr("%s.path has over %d elements, the SDK's limit", at, maxPath)
	}
	c.Path = make([]any, len(path))
	for i, el := range path {
		switch t := el.(type) {
		case string, nil:
			c.Path[i] = t
		case json.Number:
			// A non-negative integer is a value (RFC 8259 §6): 1, 1.0 and 1e0
			// select the same element.
			n, err := jsonint.NonNegative(string(t))
			if err != nil {
				return claimMeta{}, claimsErr("%s.path[%d] is a number that is not a non-negative integer an int holds (draft-ietf-oauth-sd-jwt-vc-19 §5.6.1)", at, i)
			}
			c.Path[i] = n
		default:
			return claimMeta{}, claimsErr("%s.path[%d] is not a string, null or a non-negative integer (draft-ietf-oauth-sd-jwt-vc-19 §5.6.1)", at, i)
		}
	}
	if v, ok := m["display"]; ok {
		c.hasDisplay = true
		arr, ok := v.([]any)
		if !ok {
			return claimMeta{}, claimsErr("%s.display is not an array (draft-ietf-oauth-sd-jwt-vc-19 §5.6.2)", at)
		}
		if len(arr) > maxDisplay {
			return claimMeta{}, claimsErr("%s.display has over %d elements, the SDK's limit", at, maxDisplay)
		}
		c.Display = make([]ClaimDisplay, len(arr))
		for i, e := range arr {
			dm, ok := e.(map[string]any)
			da := fmt.Sprintf("%s.display[%d]", at, i)
			if !ok {
				return claimMeta{}, claimsErr("%s is not an object (draft-ietf-oauth-sd-jwt-vc-19 §5.6.2)", da)
			}
			d := &c.Display[i]
			if d.Locale, ok = dm["locale"].(string); !ok || !wellFormedLangTag(d.Locale) {
				return claimMeta{}, claimsErr("%s.locale is absent or not a well-formed language tag (draft-ietf-oauth-sd-jwt-vc-19 §5.6.2; RFC 5646 §2.1)", da)
			}
			if d.Label, ok = dm["label"].(string); !ok {
				return claimMeta{}, claimsErr("%s.label is absent or not a string (draft-ietf-oauth-sd-jwt-vc-19 §5.6.2)", da)
			}
			if !optString(dm, "description", &d.Description) {
				return claimMeta{}, claimsErr("%s.description is not a string (draft-ietf-oauth-sd-jwt-vc-19 §5.6.2)", da)
			}
		}
	}
	if v, ok := m["mandatory"]; ok {
		c.hasMandatory = true
		if c.Mandatory, ok = v.(bool); !ok {
			return claimMeta{}, claimsErr("%s.mandatory is not a boolean (draft-ietf-oauth-sd-jwt-vc-19 §5.6.3)", at)
		}
	}
	if v, ok := m["sd"]; ok {
		c.hasSD = true
		if c.SD, _ = v.(string); c.SD != sdAlways && c.SD != sdAllowed && c.SD != sdNever {
			return claimMeta{}, claimsErr("%s.sd is not always, allowed or never (draft-ietf-oauth-sd-jwt-vc-19 §5.6.4)", at)
		}
	}
	if v, ok := m["svg_id"]; ok {
		c.hasSVGID = true
		if c.SVGID, _ = v.(string); !svgID(c.SVGID) {
			return claimMeta{}, claimsErr("%s.svg_id is not alphanumerics and underscores starting with no digit (draft-ietf-oauth-sd-jwt-vc-19 §5.6)", at)
		}
	}
	return c, nil
}

// The values of sd (§5.6.4).
const (
	sdAlways  = "always"
	sdAllowed = "allowed"
	sdNever   = "never"
)

// svgID is §5.6: only alphanumerics and underscores, not starting with a
// digit; "alphanumeric" is read as ASCII, [A-Za-z_][A-Za-z0-9_]*.
func svgID(s string) bool {
	if s == "" || ('0' <= s[0] && s[0] <= '9') {
		return false
	}
	return strings.Trim(s, "_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") == ""
}

// checkSVGIDs: §5.6, an svg_id MUST be unique within the Type Metadata.
func checkSVGIDs(claims []claimMeta) error {
	seen := map[string]bool{}
	for i, c := range claims {
		if c.SVGID == "" {
			continue
		}
		if seen[c.SVGID] {
			return claimsErr("claims[%d].svg_id is used by another claim; draft-ietf-oauth-sd-jwt-vc-19 §5.6 requires it unique", i)
		}
		seen[c.SVGID] = true
	}
	return nil
}

// optString reads the optional string property name of m into dst, and
// reports false when it is present and not a string.
func optString(m map[string]any, name string, dst *string) bool {
	v, ok := m[name]
	if !ok {
		return true
	}
	*dst, ok = v.(string)
	return ok
}

// optStringPtr is optString for a property whose presence the caller needs:
// dst stays nil when name is absent.
func optStringPtr(m map[string]any, name string, dst **string) bool {
	v, ok := m[name]
	if !ok {
		return true
	}
	s, ok := v.(string)
	if ok {
		*dst = &s
	}
	return ok
}

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: typemeta: "+format, append([]any{ErrInvalid}, a...)...)
}

func claimsErr(format string, a ...any) error {
	return fmt.Errorf("%w: typemeta: "+format, append([]any{ErrClaims}, a...)...)
}
