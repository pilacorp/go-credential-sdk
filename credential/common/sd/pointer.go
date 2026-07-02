package sd

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/pilacorp/go-credential-sdk/credential/common/util"
)

// ParsePointer parses an RFC 6901 JSON Pointer into path segments.
func ParsePointer(pointer string) []interface{} {
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

// SelectJSONLD builds a JSON-LD selection document containing only the values
// addressed by pointers, carrying @context and the id/type of every traversed
// node.
func SelectJSONLD(document map[string]interface{}, pointers []string) (map[string]interface{}, error) {
	if len(pointers) == 0 {
		return nil, nil
	}
	sel := map[string]interface{}{}
	if ctx, ok := document["@context"]; ok {
		sel["@context"] = util.DeepCopy(ctx)
	}
	initSelection(sel, document)

	for _, pointer := range pointers {
		paths := ParsePointer(pointer)
		if len(paths) == 0 {
			cloned, _ := util.DeepCopy(document).(map[string]interface{})
			return cloned, nil
		}
		if _, err := selectInto(document, paths, sel); err != nil {
			return nil, fmt.Errorf("pointer %q: %w", pointer, err)
		}
	}
	densifyArrays(sel)
	return sel, nil
}

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
				merged[k] = util.DeepCopy(val)
			}
			return merged, nil
		case []interface{}:
			return util.DeepCopy(v), nil
		default:
			return source, nil
		}
	}

	path := paths[0]
	childSource, ok := getChild(source, path)
	if !ok {
		return nil, fmt.Errorf("JSON pointer does not match document")
	}

	childSel, _ := getChild(sel, path)
	if childSel == nil {
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
			p = append(p, nil)
		}
		p[idx] = val
		return p
	default:
		return parent
	}
}

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
			if e == nil {
				continue
			}
			out = append(out, densifyArrays(e))
		}
		return out
	default:
		return v
	}
}
