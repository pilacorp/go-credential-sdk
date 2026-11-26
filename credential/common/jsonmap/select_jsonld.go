package jsonmap

import (
	"fmt"
	"strings"

	"github.com/pilacorp/go-credential-sdk/credential/internal/jsonpointer"
)

// SelectJSONLD returns the JSON-LD selection addressed by RFC 6901 pointers.
// It preserves @context and the id/type metadata of selected nodes.
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
	root := false
	for i, pointer := range pointers {
		tokens, err := jsonpointer.ParseTokens(pointer)
		if err != nil {
			return nil, err
		}
		paths[i] = tokens
		selected.add(document, tokens)
		root = root || len(tokens) == 0
	}
	if root {
		// The root pointer selects the whole document, but a pointer next to it
		// that matches nothing is still an error (VC-DI-ECDSA §3.4.12).
		for i, path := range paths {
			if !jsonpointer.Matches(document, path) {
				return nil, fmt.Errorf("pointer %.64q: JSON Pointer does not match document", pointers[i])
			}
		}
		return deepCopyJSON(document).(map[string]interface{}), nil
	}

	for i, path := range paths {
		// A pointer under another selected pointer adds nothing: the outer one
		// copies the whole value. Copying it again cost one copy per pointer.
		if selected.coversFromAbove(path) {
			if !jsonpointer.Matches(document, path) {
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
		child, ok := jsonpointer.Child(document, token)
		if !ok {
			return
		}
		document = child
		next := n.children[token]
		if next == nil {
			if n.children == nil {
				n.children = map[string]*pointerNode{}
			}
			next = &pointerNode{}
			n.children[token] = next
		}
		n = next
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
	child, ok := jsonpointer.Child(source, path[0])
	if !ok {
		return nil, fmt.Errorf("JSON Pointer does not match document")
	}
	// A hole an earlier pointer left is not selected yet: a later pointer
	// below it starts a fresh selection there.
	childSelection, _ := getJSONChild(selection, path[0])
	if _, hole := childSelection.(selectionHole); hole || childSelection == nil {
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

func getJSONChild(parent interface{}, token string) (interface{}, bool) {
	return jsonpointer.Child(parent, token)
}

func setJSONChild(parent interface{}, token string, value interface{}) interface{} {
	switch node := parent.(type) {
	case map[string]interface{}:
		node[token] = value
		return node
	case []interface{}:
		index, ok := jsonpointer.ArrayIndex(token)
		if !ok {
			return node
		}
		for len(node) <= index {
			node = append(node, selectionHole{})
		}
		node[index] = value
		return node
	default:
		return parent
	}
}

// selectionHole marks an array index the selection has not filled yet. A null
// item copied from the document is data, so it cannot mark a hole.
type selectionHole struct{}

// densifyJSONArrays removes the holes the selection left in its arrays
// (VC-DI-ECDSA §3.4.13); items copied from the document, null included, stay.
func densifyJSONArrays(value interface{}) interface{} {
	switch node := value.(type) {
	case map[string]interface{}:
		for key, child := range node {
			node[key] = densifyJSONArrays(child)
		}
	case []interface{}:
		compact := make([]interface{}, 0, len(node))
		for _, child := range node {
			if _, hole := child.(selectionHole); !hole {
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
