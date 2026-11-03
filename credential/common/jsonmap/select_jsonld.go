package jsonmap

import (
	"fmt"
	"strings"
)

// SelectJSONLD returns the JSON-LD selection addressed by RFC 6901 pointers.
// It preserves @context and the id/type metadata of selected nodes, matching
// the selectJsonLd behavior used by the selective-disclosure implementation.
func SelectJSONLD(document map[string]interface{}, pointers []string) (map[string]interface{}, error) {
	if len(pointers) == 0 {
		return nil, nil
	}
	selection := map[string]interface{}{}
	if context, ok := document["@context"]; ok {
		selection["@context"] = deepCopyJSON(context)
	}
	initJSONLDSelection(selection, document)

	for _, pointer := range pointers {
		path := parseJSONPointer(pointer)
		if len(path) == 0 {
			return deepCopyJSON(document).(map[string]interface{}), nil
		}
		if _, err := selectJSONLDInto(document, path, selection); err != nil {
			return nil, fmt.Errorf("pointer %q: %w", pointer, err)
		}
	}
	densifyJSONArrays(selection)
	return selection, nil
}

func parseJSONPointer(pointer string) []string {
	parts := strings.Split(pointer, "/")[1:]
	path := make([]string, 0, len(parts))
	for _, part := range parts {
		path = append(path, strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~"))
	}
	return path
}

func initJSONLDSelection(selection map[string]interface{}, source interface{}) {
	node, ok := source.(map[string]interface{})
	if !ok {
		return
	}
	if id, ok := node["id"].(string); ok && !strings.HasPrefix(id, "_:") {
		selection["id"] = id
	}
	if typ, ok := node["type"]; ok {
		selection["type"] = typ
	}
}

func selectJSONLDInto(source interface{}, path []string, selection interface{}) (interface{}, error) {
	if len(path) == 0 {
		switch value := source.(type) {
		case map[string]interface{}:
			merged := map[string]interface{}{}
			if existing, ok := selection.(map[string]interface{}); ok {
				for key, item := range existing {
					merged[key] = item
				}
			}
			for key, item := range value {
				merged[key] = deepCopyJSON(item)
			}
			return merged, nil
		case []interface{}:
			return deepCopyJSON(value), nil
		default:
			return source, nil
		}
	}
	child, ok := getJSONChild(source, path[0])
	if !ok {
		return nil, fmt.Errorf("JSON Pointer does not match document")
	}
	childSelection, _ := getJSONChild(selection, path[0])
	if childSelection == nil {
		if _, isArray := child.([]interface{}); isArray {
			childSelection = []interface{}{}
		} else {
			childSelection = initJSONLDSelectionMap(child)
		}
	}
	selected, err := selectJSONLDInto(child, path[1:], childSelection)
	if err != nil {
		return nil, err
	}
	return setJSONChild(selection, path[0], selected), nil
}

func initJSONLDSelectionMap(source interface{}) map[string]interface{} {
	selection := map[string]interface{}{}
	initJSONLDSelection(selection, source)
	return selection
}

func getJSONChild(parent interface{}, path string) (interface{}, bool) {
	switch value := parent.(type) {
	case map[string]interface{}:
		child, ok := value[path]
		return child, ok
	case []interface{}:
		index, ok := arrayIndex(path)
		if !ok || index >= len(value) {
			return nil, false
		}
		return value[index], true
	default:
		return nil, false
	}
}

func setJSONChild(parent interface{}, path string, value interface{}) interface{} {
	switch node := parent.(type) {
	case map[string]interface{}:
		node[path] = value
		return node
	case []interface{}:
		index, ok := arrayIndex(path)
		if !ok {
			return node
		}
		for len(node) <= index {
			node = append(node, nil)
		}
		node[index] = value
		return node
	default:
		return parent
	}
}

func arrayIndex(token string) (int, bool) {
	if token == "" || (len(token) > 1 && token[0] == '0') {
		return 0, false
	}
	index := 0
	for _, char := range token {
		if char < '0' || char > '9' {
			return 0, false
		}
		index = index*10 + int(char-'0')
	}
	return index, true
}

func densifyJSONArrays(value interface{}) interface{} {
	switch node := value.(type) {
	case map[string]interface{}:
		for key, child := range node {
			node[key] = densifyJSONArrays(child)
		}
	case []interface{}:
		compact := make([]interface{}, 0, len(node))
		for _, child := range node {
			if child != nil {
				compact = append(compact, densifyJSONArrays(child))
			}
		}
		return compact
	}
	return value
}

func deepCopyJSON(value interface{}) interface{} {
	switch node := value.(type) {
	case map[string]interface{}:
		copy := make(map[string]interface{}, len(node))
		for key, child := range node {
			copy[key] = deepCopyJSON(child)
		}
		return copy
	case []interface{}:
		copy := make([]interface{}, len(node))
		for i, child := range node {
			copy[i] = deepCopyJSON(child)
		}
		return copy
	default:
		return value
	}
}
