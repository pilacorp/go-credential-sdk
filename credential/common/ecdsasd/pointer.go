package ecdsasd

import (
	"fmt"
	"strconv"
	"strings"
)

// parsePointer parses an RFC 6901 JSON Pointer into path segments. Numeric
// segments become int (array indexes); escaped segments are unescaped
// (~1 -> "/", ~0 -> "~"). Ports digitalbazaar di-sd-primitives parsePointer.
func parsePointer(pointer string) []interface{} {
	parts := strings.Split(pointer, "/")
	if len(parts) > 0 {
		parts = parts[1:]
	}
	parsed := make([]interface{}, 0, len(parts))
	for _, part := range parts {
		if !strings.Contains(part, "~") {
			if n, err := strconv.Atoi(part); err == nil {
				parsed = append(parsed, n)
				continue
			}
			parsed = append(parsed, part)
			continue
		}
		un := strings.ReplaceAll(part, "~1", "/")
		un = strings.ReplaceAll(un, "~0", "~")
		parsed = append(parsed, un)
	}
	return parsed
}

// checkPointers refuses a pointer a caller supplies that is not "" and does not
// start with "/" (RFC 6901 §3), or that matches nothing in document
// (VC-DI-ECDSA §3.4.12). parsePointer drops the first token, so
// "credentialSubject" would read as "", the whole document. CreateBaseProof and
// DeriveProof check their pointers here. selectJsonLd does not: it also reads
// the mandatory pointers stored in an issued base proof, which released versions
// signed without these checks.
func checkPointers(document map[string]interface{}, pointers []string) error {
	for _, pointer := range pointers {
		if pointer != "" && !strings.HasPrefix(pointer, "/") {
			return fmt.Errorf("pointer %.64q must start with /", pointer)
		}
	}
	for _, pointer := range pointers {
		if !matchesPointer(document, parsePointer(pointer)) {
			return fmt.Errorf("pointer %.64q: JSON pointer does not match document", pointer)
		}
	}
	return nil
}

// TODO: Reuse jsonmap.SelectJSONLD here so JSON-LD pointer selection has one
// implementation across selective disclosure and rendering.
//
// selectJsonLd builds a JSON-LD selection document containing only the values
// addressed by pointers, carrying @context and the id/type of every traversed
// node. Ports digitalbazaar di-sd-primitives selectJsonLd (includeTypes=true).
// Like the reference, it reads a pointer by dropping its first token, and
// returns the whole document when it reaches the root pointer: a stored pointer
// is read as it was issued. checkPointers is for a caller's pointers.
func selectJsonLd(document map[string]interface{}, pointers []string) (map[string]interface{}, error) {
	if len(pointers) == 0 {
		return nil, nil
	}
	sel := map[string]interface{}{}
	if ctx, ok := document["@context"]; ok {
		sel["@context"] = deepCopy(ctx)
	}
	initSelection(sel, document)

	for _, pointer := range pointers {
		paths := parsePointer(pointer)
		if len(paths) == 0 {
			cloned, _ := deepCopy(document).(map[string]interface{})
			return cloned, nil
		}
		if _, err := selectInto(document, paths, sel); err != nil {
			return nil, fmt.Errorf("pointer %.64q: %w", pointer, err)
		}
	}
	densifyArrays(sel)
	return sel, nil
}

func matchesPointer(document interface{}, path []interface{}) bool {
	for _, token := range path {
		child, ok := getChild(document, token)
		if !ok {
			return false
		}
		document = child
	}
	return true
}

// selectInto walks paths into source, blending the selection into sel (the
// current selection node), and returns the (possibly grown) selection node so
// slice growth propagates to the parent.
func selectInto(source interface{}, paths []interface{}, sel interface{}) (interface{}, error) {
	if len(paths) == 0 {
		switch v := source.(type) {
		case map[string]interface{}:
			merged := map[string]interface{}{}
			if sm, ok := sel.(map[string]interface{}); ok {
				for k, val := range sm {
					merged[k] = val
				}
			}
			for k, val := range v {
				merged[k] = deepCopy(val)
			}
			return merged, nil
		case []interface{}:
			return deepCopy(v), nil
		default:
			return source, nil
		}
	}

	path := paths[0]
	childSource, ok := getChild(source, path)
	if !ok {
		return nil, fmt.Errorf("JSON pointer does not match document")
	}

	// A hole an earlier pointer left is not selected yet: a later pointer
	// below it starts a fresh selection there.
	childSel, _ := getChild(sel, path)
	if _, hole := childSel.(selectionHole); hole || childSel == nil {
		if _, isArr := childSource.([]interface{}); isArr {
			childSel = []interface{}{}
		} else {
			childSel = initSelection(map[string]interface{}{}, childSource)
		}
	}

	newChild, err := selectInto(childSource, paths[1:], childSel)
	if err != nil {
		return nil, err
	}
	return setChild(sel, path, newChild), nil
}

// initSelection copies the non-blank id and type from source into sel (per the
// spec: type is referenced, not cloned). Returns sel.
func initSelection(sel map[string]interface{}, source interface{}) map[string]interface{} {
	m, ok := source.(map[string]interface{})
	if !ok {
		return sel
	}
	if id, ok := m["id"].(string); ok && !strings.HasPrefix(id, "_:") {
		sel["id"] = id
	}
	if typ, ok := m["type"]; ok {
		sel["type"] = typ
	}
	return sel
}

func getChild(parent interface{}, path interface{}) (interface{}, bool) {
	switch p := parent.(type) {
	case map[string]interface{}:
		key, ok := path.(string)
		if !ok {
			return nil, false
		}
		v, ok := p[key]
		return v, ok
	case []interface{}:
		idx, ok := path.(int)
		if !ok || idx < 0 || idx >= len(p) {
			return nil, false
		}
		return p[idx], true
	default:
		return nil, false
	}
}

func setChild(parent interface{}, path interface{}, val interface{}) interface{} {
	switch p := parent.(type) {
	case map[string]interface{}:
		if key, ok := path.(string); ok {
			p[key] = val
		}
		return p
	case []interface{}:
		idx, ok := path.(int)
		if !ok {
			return p
		}
		for len(p) <= idx {
			p = append(p, selectionHole{})
		}
		p[idx] = val
		return p
	default:
		return parent
	}
}

// selectionHole marks an array index the selection has not filled. A null item
// copied from the document is data, so it cannot mark a hole.
type selectionHole struct{}

// densifyArrays removes the holes the selection left in its arrays
// (VC-DI-ECDSA §3.4.13); items copied from the document, null included, stay.
func densifyArrays(v interface{}) interface{} {
	switch t := v.(type) {
	case map[string]interface{}:
		for k, val := range t {
			t[k] = densifyArrays(val)
		}
		return t
	case []interface{}:
		out := make([]interface{}, 0, len(t))
		for _, e := range t {
			if _, hole := e.(selectionHole); hole {
				continue
			}
			out = append(out, densifyArrays(e))
		}
		return out
	default:
		return v
	}
}
