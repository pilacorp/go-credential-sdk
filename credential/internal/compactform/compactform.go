// Package compactform checks that the JSON of a verified JSON-LD credential or
// presentation says, for the properties the SDK itself reads by name, what its
// signed meaning says. It enforces VC Data Model 2.0 §7.1 step 2 (a verifier
// refuses a document that is not compacted JSON-LD) for those properties,
// using the recompaction of VC Data Integrity 1.0 §4.6
// against the bundled contexts the document names.
//
// A proof over the canonical RDF accepts any JSON with the same RDF, so a
// holder can rename a property with an alias, write it as a full IRI or move it
// under @nest, and a reader that looks the property up by name would miss it,
// or read another signed value under its name. The check compacts the document
// against the known context (the bundled contexts it names) and against its own
// @context, and compares:
//
//   - a single-value property (issuer id, validFrom, validUntil, issuanceDate,
//     expirationDate) must equal its value in the known form, so one the known
//     contexts do not define must be absent;
//   - type and every node the SDK reads (credentialSubject, credentialStatus,
//     credentialSchema, renderMethod, issuer, holder) must be written in the
//     own form and have as many values as the known form, and every member the
//     known form names by a term must hold, under that name, the known value,
//     at any depth.
//
// Anywhere in the document, the known form must hold no @index and, for a
// credential, must name every VC Data Model term it holds: either failure means the SDK would read an unsigned
// member or miss a signed one.
//
// A member a bundled context does not define comes out of the known form as a
// full or compact IRI and is checked only for being written in compacted form:
// the own form comes from the holder's context and binds nothing. Validating
// such contexts (VC Data Integrity 1.0 §2.4.1) is the application's duty.
//
// The check compares names and values, not the tree: statements about one node
// that the issuer wrote in two node objects with the same id can be moved
// between them, since the RDF is the same.
package compactform

import (
	"fmt"
	"reflect"
	"slices"
	"strings"

	"github.com/pilacorp/go-credential-sdk/credential/common/processor"
	"github.com/pilacorp/go-credential-sdk/credential/internal/errtext"
)

// Rules names the properties a document type is checked on.
type Rules struct {
	Single []string // single values compared with the known form
	// OwnSingle are single values compared with the known form where a bundled
	// context defines them and with the own form otherwise: the validity dates
	// of a presentation, an SDK extension no bundled context defines. The own
	// form binds nothing, so an alias can hide them; a presentation's freshness
	// rests on its challenge and domain.
	OwnSingle []string
	Nodes     []string // nodes compared as described in the package comment
	Counts    []string // compared by number of values only (embedded credentials)
	// NamedVCDMTerms refuses a VC Data Model term the known form can only
	// write as a full IRI. A credential needs it: the issuer signed it and the
	// holder must not relabel its context. A presentation is signed by its
	// holder, who may map an extension term to a VCDM IRI (vp godoc).
	NamedVCDMTerms bool
}

// Check compares body (a document without its proof) with its compacted forms
// under rules. The error wraps processor.ErrNotCompactedForm and names the
// property path.
//
// limits bounds the JSON-LD work of the compactions (processor.JSONLDLimits).
func Check(body map[string]interface{}, rules Rules, limits processor.JSONLDLimits) error {
	own, known, err := processor.CompactedForms(body, limits)
	if err != nil {
		return err
	}
	fail := func(path string) error {
		// Keys come from the document: quoted, so a control character in one
		// cannot forge a log line.
		return fmt.Errorf("%w: %q", processor.ErrNotCompactedForm, errtext.Clip(path))
	}

	// Compaction drops null array elements, except inside a JSON literal; a
	// reader still sees one where it shifts the signed values. (Compaction
	// spreads an array literal's elements as values at every depth, so a
	// literal it changes, such as [1], [[1], [2]], [] or [null], is refused:
	// closed, not open.)
	if path, found := nullElement(body, own, ""); found {
		return fail(path)
	}
	for _, k := range rules.Single {
		if !sameValue(single(body[k]), single(known[k]), true) {
			return fail(k)
		}
	}
	for _, k := range rules.OwnSingle {
		want, defined := known[k]
		if !defined {
			want = own[k]
		}
		if !sameValue(single(body[k]), single(want), true) {
			return fail(k)
		}
	}
	if !sameValue(body["type"], own["type"], false) || !sameTypes(body["type"], known["type"]) {
		return fail("type")
	}
	for _, k := range rules.Nodes {
		if !sameValue(body[k], own[k], false) || len(values(body[k])) != len(values(known[k])) {
			return fail(k)
		}
		if path, ok := bound(body[k], known[k], k); !ok {
			return fail(path)
		}
	}
	for _, k := range rules.Counts {
		if len(values(body[k])) != len(values(known[k])) {
			return fail(k)
		}
	}
	// Embedded credentials are graphs the presentation's context compacts; each
	// is checked against its own contexts when it is verified.
	top := make(map[string]interface{}, len(known))
	for k, v := range known {
		top[k] = v
	}
	for _, k := range rules.Counts {
		delete(top, k)
		delete(top, countsIRI(k))
	}
	if path, ok := unnamed(top, "", rules.NamedVCDMTerms); !ok {
		return fail(path)
	}
	return nil
}

// vcdmVocabularies are the vocabularies of the VC Data Model terms the SDK
// reads (credentials v1 and v2 share the first). A term of theirs comes out of
// the known form as a full IRI only when the document's bundled contexts do not
// define it: a VCDM 2.0 credential relabelled with the v1 context, where the
// status# terms (BitstringStatusListEntry) and 2.0 additions such as
// renderMethod are not terms. The SDK reads those by name, so it would miss
// them. This is SDK policy (VC Data Integrity 1.0 §4.6 allows further errors),
// not a rule of either data model.
var vcdmVocabularies = []string{
	"https://www.w3.org/2018/credentials#",
	"https://www.w3.org/ns/credentials/status#",
}

// unnamed walks the known form and returns the path of a member the SDK cannot
// read by name: an @index, or, when vcdm is set, a VCDM term as a full IRI
// (key or type). An
// @index yields no triple, so nothing signs it, and no bundled context aliases
// or uses it; a raw member that compacts to it is an unsigned value under a
// name of the holder's choosing.
func unnamed(v interface{}, path string, vcdm bool) (string, bool) {
	switch t := v.(type) {
	case map[string]interface{}:
		for _, key := range sortedKeys(t) {
			e := t[key]
			if noValue(e) {
				continue // no triple: nothing to misread
			}
			sub := key
			if path != "" {
				sub = path + "." + key
			}
			if key == "@index" || (vcdm && isVCDMIRI(key)) {
				return sub, false
			}
			if vcdm && key == "type" {
				for _, ty := range values(e) {
					if s, ok := ty.(string); ok && isVCDMIRI(s) {
						return sub, false
					}
				}
			}
			if p, ok := unnamed(e, sub, vcdm); !ok {
				return p, false
			}
		}
	case []interface{}:
		for i, e := range t {
			if p, ok := unnamed(e, fmt.Sprintf("%s[%d]", path, i), vcdm); !ok {
				return p, false
			}
		}
	}
	return path, true
}

// countsIRI is the full IRI a Counts key compacts to when no term matches its
// value (an empty verifiableCredential).
func countsIRI(k string) string { return vcdmVocabularies[0] + k }

func isVCDMIRI(s string) bool {
	// The v1 context defines the prefix cred for the first vocabulary, so such
	// an IRI can also come out as a compact IRI.
	if strings.HasPrefix(s, "cred:") {
		return true
	}
	for _, ns := range vcdmVocabularies {
		if strings.HasPrefix(s, ns) {
			return true
		}
	}
	return false
}

// bound reports whether raw holds, under every term the known form uses, the
// known value, and returns the path where it does not. Full and compact IRI
// keys are skipped: no bundled term defines them. type is compared with
// sameTypes, since a type a bundled context does not define is an IRI there.
//
// The own context may give a term a datatype, a language or a container that
// the known term lacks, so the same signed value is written differently in the
// two forms: a value object, {"@list": ...}, a list of language values, a map
// keyed by id. Those are compared by the values they hold, not by shape.
func bound(raw, known interface{}, path string) (string, bool) {
	known = unwrap(known)
	if k, ok := known.(map[string]interface{}); ok && k["@value"] != nil && isJSONLiteral(k) {
		// A JSON literal is compared before raw is unwrapped: a one-element
		// array is its own value there. Compaction returns the literal and
		// "add value" spreads an array (JSON-LD 1.1 API §1.4.1, §6.1.2 steps 7
		// and 12.8.10; json-ld-api#560), so [x] comes out as x. Matching the
		// two would let a holder swap a signed [x] with a signed x, so such
		// literals are refused.
		return path, reflect.DeepEqual(valueOf(raw), k["@value"])
	}
	raw = unwrap(raw)
	if r, ok := raw.(map[string]interface{}); ok && r["@value"] == nil {
		if p, ok, handled := boundContainer(r, known, path); handled {
			return p, ok
		}
	}
	if k, ok := known.(map[string]interface{}); ok {
		if v, isValue := k["@value"]; isValue {
			if isJSONLiteral(k) {
				// A JSON literal is signed as the exact JSON: no shape is lost.
				return path, reflect.DeepEqual(valueOf(raw), v)
			}
			return path, sameValue(valueOf(raw), v, false)
		}
		for _, kw := range []string{"@list", "@set"} {
			if l, isList := k[kw]; isList && len(k) == 1 {
				if r, ok := raw.(map[string]interface{}); ok && len(r) == 1 && r[kw] != nil {
					raw = r[kw]
				}
				return bound(raw, l, path)
			}
		}
	}
	switch k := known.(type) {
	case map[string]interface{}:
		r, ok := raw.(map[string]interface{})
		if !ok {
			// A node reference compacts to its id, or, for a term typed
			// @vocab, to the id relative to the examples vocabulary.
			if id, isID := k["id"]; isID && len(k) == 1 {
				if s, isString := raw.(string); isString && id == examplesVocab+s {
					return path, true
				}
				return path, sameValue(raw, id, false)
			}
			return path, false
		}
		for _, key := range sortedKeys(k) {
			kv := k[key]
			if isIRI(key) || strings.HasPrefix(key, "@") {
				continue
			}
			sub := path + "." + key
			if key == "type" {
				if !sameTypes(r[key], kv) {
					return sub, false
				}
				continue
			}
			if p, ok := bound(r[key], kv, sub); !ok {
				return p, false
			}
		}
		return path, true
	case []interface{}:
		r := values(raw)
		if len(r) != len(k) {
			return path, false
		}
		for i := range k {
			if p, ok := bound(r[i], k[i], fmt.Sprintf("%s[%d]", path, i)); !ok {
				return p, false
			}
		}
		return path, true
	case nil:
		return path, normalize(raw) == nil
	default:
		return path, sameValue(valueOf(raw), known, false)
	}
}

// boundContainer compares a raw map that the own context reads as a language
// map or an id map with the known values it stands for, and passes any other
// map to boundTypeMap. handled is false when raw is not such a map.
func boundContainer(raw map[string]interface{}, known interface{}, path string) (string, bool, bool) {
	items := append([]interface{}(nil), values(known)...)
	if len(items) == 0 {
		return path, false, false
	}
	_, hasNone := raw["@none"]
	langs, ids := true, true
	for i, it := range items {
		if s, isString := it.(string); isString && hasNone {
			// An untagged string under @none compacts to the plain string.
			it = map[string]interface{}{"@value": s}
			items[i] = it
		}
		m, ok := it.(map[string]interface{})
		if !ok {
			return path, false, false
		}
		_, isValue := m["@value"]
		if _, tagged := m["@language"]; !isValue || (!tagged && !hasNone) {
			langs = false
		}
		if id, ok := m["id"].(string); !ok || raw[id] == nil {
			ids = false
		}
	}
	// A node holds its own id; an id map is keyed by the ids it holds.
	if _, isNode := raw["id"]; isNode {
		ids = false
	}
	switch {
	case langs:
		var got []interface{}
		for _, lang := range sortedKeys(raw) {
			for _, v := range values(raw[lang]) {
				item := map[string]interface{}{"@value": v}
				if lang != "@none" {
					item["@language"] = lang
				}
				got = append(got, item)
			}
		}
		return path, sameLanguageValues(got, items), true
	case ids:
		if len(raw) != len(items) {
			return path, false, true
		}
		for _, it := range items {
			node := it.(map[string]interface{})
			id, _ := node["id"].(string)
			r, ok := raw[id].(map[string]interface{})
			if !ok {
				return path, false, true
			}
			withID := make(map[string]interface{}, len(r)+1)
			for k, v := range r {
				withID[k] = v
			}
			withID["id"] = id
			if p, ok := bound(withID, node, path+"."+id); !ok {
				return p, false, true
			}
		}
		return path, true, true
	}
	return boundTypeMap(raw, items, path)
}

// boundTypeMap compares a raw map the own context reads as a type map (keys
// are types, values nodes or node references) with the known nodes, as a
// multiset: the map key is one more type of each node under it.
func boundTypeMap(raw map[string]interface{}, items []interface{}, path string) (string, bool, bool) {
	if len(raw) == 0 {
		return path, false, false // an empty node, not a map
	}
	if _, isNode := raw["id"]; isNode {
		return path, false, false
	}
	if _, isNode := raw["type"]; isNode {
		return path, false, false
	}
	known := map[string]bool{}
	for _, it := range items {
		m, ok := it.(map[string]interface{})
		if !ok {
			return path, false, false
		}
		for _, t := range values(m["type"]) {
			if s, ok := t.(string); ok {
				known[s] = true
			}
		}
	}
	for k := range raw {
		if !known[k] {
			return path, false, false
		}
	}
	var nodes []map[string]interface{}
	for _, t := range sortedKeys(raw) {
		for _, v := range values(raw[t]) {
			switch n := v.(type) {
			case string:
				nodes = append(nodes, map[string]interface{}{"id": n, "type": t})
			case map[string]interface{}:
				node := make(map[string]interface{}, len(n)+1)
				for k, e := range n {
					node[k] = e
				}
				node["type"] = append([]interface{}{t}, values(n["type"])...)
				nodes = append(nodes, node)
			default:
				return path, false, true
			}
		}
	}
	if len(nodes) != len(items) {
		return path, false, true
	}
	// Both sides come from the same raw map: json-gold reads a type map's keys
	// in sorted order (the REC orders them only when ordered is true, §5.1.2
	// step 13.8.3) and keeps each key's array order, as sortedKeys does, so
	// node i stands for item i.
	for i, n := range nodes {
		if _, ok := bound(n, items[i], path); !ok {
			return path, false, true
		}
	}
	return path, true, true
}

// sameLanguageValues compares two lists of language values as sets: a
// language map has no order.
func sameLanguageValues(a, b []interface{}) bool {
	if len(a) != len(b) {
		return false
	}
	key := func(v interface{}) string {
		m := v.(map[string]interface{})
		return fmt.Sprintf("%v\x00%v", strings.ToLower(fmt.Sprint(m["@language"])), m["@value"])
	}
	seen := map[string]int{}
	for _, v := range a {
		seen[key(v)]++
	}
	for _, v := range b {
		if seen[key(v)] == 0 {
			return false
		}
		seen[key(v)]--
	}
	return true
}

// nullElement returns the path of the first null array element in raw that
// the own form does not have at that path.
func nullElement(raw, own interface{}, path string) (string, bool) {
	switch t := raw.(type) {
	case map[string]interface{}:
		o, _ := own.(map[string]interface{})
		for _, k := range sortedKeys(t) {
			sub := k
			if path != "" {
				sub = path + "." + k
			}
			if p, found := nullElement(t[k], o[k], sub); found {
				return p, true
			}
		}
	case []interface{}:
		o, isArray := own.([]interface{})
		if !isArray && len(t) == 1 {
			o = []interface{}{own} // compactArrays wrote the element alone
		}
		for i, e := range t {
			if e == nil {
				// Only a JSON literal keeps a null: the own form then holds
				// this exact array. Each such array is compared once, so the
				// walk stays linear in the size of the document.
				if isArray && reflect.DeepEqual(t, o) {
					return path, false
				}
				return fmt.Sprintf("%s[%d]", path, i), true
			}
		}
		for i, e := range t {
			var oe interface{}
			if len(o) == len(t) {
				oe = o[i]
			}
			if p, found := nullElement(e, oe, fmt.Sprintf("%s[%d]", path, i)); found {
				return p, true
			}
		}
	}
	return path, false
}

// examplesVocab is the @vocab of the bundled examples context, the only
// bundled context with one.
const examplesVocab = "https://www.w3.org/ns/credentials/examples#"

// isJSONLiteral reports a value object of type @json ("type" is the bundled
// alias of @type).
func isJSONLiteral(v map[string]interface{}) bool {
	return v["@type"] == "@json" || v["type"] == "@json"
}

// valueOf returns the @value of a raw value object, or raw itself.
func valueOf(raw interface{}) interface{} {
	if m, ok := raw.(map[string]interface{}); ok {
		if v, isValue := m["@value"]; isValue {
			return v
		}
	}
	return raw
}

// single reads a single-value property as the SDK readers do: an object is
// read for its id (issuer may be an object holding an id).
func single(v interface{}) interface{} {
	if m, ok := v.(map[string]interface{}); ok {
		return m["id"]
	}
	return v
}

// sameTypes reports whether raw has as many types as known and holds every
// known type that is a bundled term rather than an IRI.
func sameTypes(raw, known interface{}) bool {
	r, k := values(raw), values(known)
	if len(r) != len(k) {
		return false
	}
	have := map[interface{}]bool{}
	for _, t := range r {
		have[t] = true
	}
	for _, t := range k {
		if s, ok := t.(string); ok && !isIRI(s) && !have[s] {
			return false
		}
	}
	return true
}

// sortedKeys gives the walks a fixed order, so the same document always fails
// on the same path.
func sortedKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func isIRI(s string) bool { return strings.Contains(s, ":") }

// sameValue reports whether a raw value says what a compacted value says. A
// member whose value is null (which expansion drops) or an empty array (which,
// outside a @list container, yields no triple) is ignored. Unless single is set, a
// one-element array equals its element, as compactArrays makes it for a term
// with no @set or @list container (JSON-LD 1.1 API §6.1.2 step 3.4), and an
// object holding only a string id equals that id, as value compaction of an
// @id-typed term makes it (§6.3.2 step 6.1). single is for a property VC Data
// Model 2.0 §6 requires as a single value (issuer, validFrom, validUntil): an
// array is not its compacted form.
func sameValue(raw, compacted interface{}, single bool) bool {
	if single {
		if _, isArray := raw.([]interface{}); isArray {
			return false
		}
	}
	return reflect.DeepEqual(normalize(raw), normalize(compacted))
}

// values returns v as a list: an array as it is, nil as none, any other value
// as a list of one.
func values(v interface{}) []interface{} {
	switch t := v.(type) {
	case nil:
		return nil
	case []interface{}:
		return dropNulls(t)
	default:
		return []interface{}{t}
	}
}

// noValue reports whether v is null or an array of such values, what
// normalize turns into nil, without walking objects: unnamed asks it at every
// level, so it must not cost the size of the subtree.
func noValue(v interface{}) bool {
	switch t := v.(type) {
	case nil:
		return true
	case []interface{}:
		for _, e := range t {
			if !noValue(e) {
				return false
			}
		}
		return true
	}
	return false
}

// dropNulls returns a without its null elements, which expansion drops
// (JSON-LD 1.1 API §5.1.2, array expansion).
func dropNulls(a []interface{}) []interface{} {
	for i, e := range a {
		if e == nil {
			out := append([]interface{}{}, a[:i]...)
			for _, e := range a[i+1:] {
				if e != nil {
					out = append(out, e)
				}
			}
			return out
		}
	}
	return a
}

// unwrap returns the element of a one-element array, nil for an empty one.
func unwrap(v interface{}) interface{} {
	if a, ok := v.([]interface{}); ok {
		a = dropNulls(a)
		switch len(a) {
		case 0:
			return nil
		case 1:
			return a[0]
		}
	}
	return v
}

func normalize(v interface{}) interface{} {
	switch val := v.(type) {
	case []interface{}:
		val = dropNulls(val)
		switch len(val) {
		case 0:
			return nil
		case 1:
			return normalize(val[0])
		}
		out := make([]interface{}, len(val))
		for i, e := range val {
			out[i] = normalize(e)
		}
		return out
	case map[string]interface{}:
		out := make(map[string]interface{}, len(val))
		for k, e := range val {
			if n := normalize(e); n != nil {
				out[k] = n
			}
		}
		if id, ok := out["id"].(string); ok && len(out) == 1 {
			return id
		}
		return out
	default:
		return v
	}
}
