package jsonmap

import (
	"fmt"
	"strconv"
	"strings"
)

// SelectJSONLD returns the JSON-LD selection addressed by RFC 6901 pointers.
// It preserves @context and the id/type metadata of selected nodes. The copy
// in ecdsasd differs on numeric object keys, leading zeros and a missing
// leading "/".
func SelectJSONLD(document map[string]interface{}, pointers []string) (map[string]interface{}, error) {
	if len(pointers) == 0 {
		return nil, nil
	}
	selection := map[string]interface{}{}
	if context, ok := document["@context"]; ok {
		selection["@context"] = deepCopyJSON(context)
	}
	initJSONLDSelection(selection, document)
	paths := make([][]string, len(pointers))
	selected := &pointerNode{}
	for i, pointer := range pointers {
		if pointer == "" || strings.HasPrefix(pointer, "/") {
			paths[i] = parseJSONPointer(pointer)
			selected.add(document, paths[i])
		}
	}

	for i, path := range paths {
		if pointers[i] != "" && !strings.HasPrefix(pointers[i], "/") {
			return nil, fmt.Errorf("pointer %.64q must start with /", pointers[i])
		}
		if len(path) == 0 {
			return deepCopyJSON(document).(map[string]interface{}), nil
		}
		// A pointer under another selected pointer adds nothing: the outer one
		// copies the whole value. Copying it again cost one copy per pointer.
		if selected.coversFromAbove(path) {
			if !matchesJSONPointer(document, path) {
				return nil, fmt.Errorf("pointer %.64q: JSON Pointer does not match document", pointers[i])
			}
			continue
		}
		if !selected.takeFirst(path) {
			continue
		}
		if _, err := selectJSONLDInto(document, path, selection); err != nil {
			return nil, fmt.Errorf("pointer %.64q: %w", pointers[i], err)
		}
	}
	densifyJSONArrays(selection)
	return selection, nil
}

// pointerNode is one reference token in the tree of requested pointers.
type pointerNode struct {
	children map[string]*pointerNode
	// requested marks the end of a pointer; done marks that it was selected.
	requested, done bool
}

// add indexes path only as deep as it matches document. A pointer that
// matches nothing covers no other pointer, and its tokens are not kept.
func (n *pointerNode) add(document interface{}, path []string) {
	for _, token := range path {
		next, ok := getJSONChild(document, token)
		if !ok {
			return
		}
		document = next
		child := n.children[token]
		if child == nil {
			if n.children == nil {
				n.children = map[string]*pointerNode{}
			}
			child = &pointerNode{}
			n.children[token] = child
		}
		n = child
	}
	n.requested = true
}

// coversFromAbove reports whether a requested pointer is a proper prefix of
// path. The root pointer is left out: it returns the whole document on its own.
func (n *pointerNode) coversFromAbove(path []string) bool {
	for _, token := range path[:len(path)-1] {
		n = n.children[token]
		if n == nil {
			return false
		}
		if n.requested {
			return true
		}
	}
	return false
}

// takeFirst reports whether path has not been selected yet, and marks it.
func (n *pointerNode) takeFirst(path []string) bool {
	for _, token := range path {
		n = n.children[token]
		if n == nil {
			return true
		}
	}
	first := !n.done
	n.done = true
	return first
}

func matchesJSONPointer(document interface{}, path []string) bool {
	for _, token := range path {
		child, ok := getJSONChild(document, token)
		if !ok {
			return false
		}
		document = child
	}
	return true
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
		// Copied: compacting arrays in the selection would write into the document.
		selection["type"] = deepCopyJSON(typ)
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
		if !ok || index < 0 || index >= len(value) {
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

// arrayIndex parses an RFC 6901 array-index token: "0" or a decimal number
// without leading zeros. Tokens that overflow int are rejected rather than
// wrapping to a negative index.
func arrayIndex(token string) (int, bool) {
	if token == "" || (len(token) > 1 && token[0] == '0') {
		return 0, false
	}
	for i := 0; i < len(token); i++ {
		if token[i] < '0' || token[i] > '9' {
			return 0, false
		}
	}
	// The digit check above excludes signs, so Atoi only fails on overflow.
	index, err := strconv.Atoi(token)
	if err != nil || index < 0 {
		return 0, false
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
