// Package jsonpointer implements RFC 6901 JSON Pointer parsing and resolution
// for JSON-like Go values (map[string]interface{} and []interface{}).
//
// A token is an array index only when the parent value is a []interface{}; for
// map[string]interface{} parents every token is a key, including all-digit
// tokens like "3". Array indexes follow RFC 6901 §4: "0" or a decimal number
// with no leading zeros ("1", "10", not "01" or "+1").
package jsonpointer

import (
	"fmt"
	"strconv"
	"strings"
)

// Validate checks whether pointer is a syntactically valid RFC 6901 JSON
// Pointer. The empty string is the root pointer and is valid. Any other pointer
// must start with "/" and use only "~0" and "~1" as escape sequences.
func Validate(pointer string) error {
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

// ParseTokens splits an RFC 6901 pointer into unescaped reference tokens.
// The root pointer "" returns nil, nil. A non-empty pointer that does not
// start with "/" returns an error. Tokens containing a "~" not followed by
// "0" or "1" are rejected (RFC 6901 §4).
func ParseTokens(pointer string) ([]string, error) {
	if pointer == "" {
		return nil, nil
	}
	if !strings.HasPrefix(pointer, "/") {
		return nil, fmt.Errorf("pointer %.64q must start with /", pointer)
	}
	parts := strings.Split(pointer[1:], "/")
	tokens := make([]string, len(parts))
	for i, part := range parts {
		if err := validateEscapes(part); err != nil {
			return nil, fmt.Errorf("pointer %.64q: %w", pointer, err)
		}
		tokens[i] = Unescape(part)
	}
	return tokens, nil
}

// validateEscapes checks that every ~ in a raw (pre-unescape) reference token
// is followed by 0 or 1. RFC 6901 §4: "… the string '~' (%x7E) is not used".
func validateEscapes(raw string) error {
	for i := 0; i < len(raw); i++ {
		if raw[i] != '~' {
			continue
		}
		if i+1 >= len(raw) || (raw[i+1] != '0' && raw[i+1] != '1') {
			return fmt.Errorf("invalid ~ escape in token %.64q", raw)
		}
		i++ // skip the escape character
	}
	return nil
}

// Unescape replaces ~1 with "/" and ~0 with "~" in a single reference token
// (RFC 6901 §4). The order matters: ~1 is replaced first, then ~0.
func Unescape(token string) string {
	token = strings.ReplaceAll(token, "~1", "/")
	token = strings.ReplaceAll(token, "~0", "~")
	return token
}

// Escape replaces "~" with "~0" and "/" with "~1" in a single reference token
// (RFC 6901 §4). The order matters: "~" is replaced first, then "/".
func Escape(token string) string {
	token = strings.ReplaceAll(token, "~", "~0")
	token = strings.ReplaceAll(token, "/", "~1")
	return token
}

// ArrayIndex parses an RFC 6901 array-index token: "0" or a decimal number
// without leading zeros. Tokens that overflow int are rejected rather than
// wrapping to a negative index. Signs, spaces, and non-digit characters are
// rejected.
func ArrayIndex(token string) (int, bool) {
	if token == "" || (len(token) > 1 && token[0] == '0') {
		return 0, false
	}
	for i := 0; i < len(token); i++ {
		if token[i] < '0' || token[i] > '9' {
			return 0, false
		}
	}
	index, err := strconv.Atoi(token)
	if err != nil || index < 0 {
		return 0, false
	}
	return index, true
}

// Resolve resolves an RFC 6901 JSON Pointer against a JSON-like value
// (map[string]interface{} and []interface{}). The root pointer "" returns the
// document itself. A non-empty pointer that does not start with "/" returns an
// error.
//
// A token is used as an array index only when the parent is a []interface{};
// for map[string]interface{} parents every token is a key lookup, including
// all-digit tokens like "3".
func Resolve(document interface{}, pointer string) (interface{}, error) {
	if pointer == "" {
		return document, nil
	}
	tokens, err := ParseTokens(pointer)
	if err != nil {
		return nil, err
	}
	return ResolveTokens(document, tokens)
}

// ResolveTokens walks the given unescaped reference tokens into document,
// returning the addressed value.
func ResolveTokens(document interface{}, tokens []string) (interface{}, error) {
	current := document
	for _, token := range tokens {
		child, err := GetChild(current, token)
		if err != nil {
			return nil, err
		}
		current = child
	}
	return current, nil
}

// GetChild returns the child of parent addressed by a single unescaped
// reference token. For a map it is a key lookup; for a slice it parses the
// token as an RFC 6901 array index.
func GetChild(parent interface{}, token string) (interface{}, error) {
	switch p := parent.(type) {
	case map[string]interface{}:
		v, ok := p[token]
		if !ok {
			return nil, fmt.Errorf("JSON Pointer segment %.64q not found", token)
		}
		return v, nil
	case []interface{}:
		index, ok := ArrayIndex(token)
		if !ok || index >= len(p) {
			return nil, fmt.Errorf("JSON Pointer array index %.64q is invalid or out of range", token)
		}
		return p[index], nil
	default:
		return nil, fmt.Errorf("cannot resolve JSON Pointer segment %.64q through %T", token, parent)
	}
}

// Matches reports whether the pointer addresses a value in document. It
// performs the same token walk as ResolveTokens, returning false instead of
// an error when a token does not match.
func Matches(document interface{}, tokens []string) bool {
	current := document
	for _, token := range tokens {
		child, err := GetChild(current, token)
		if err != nil {
			return false
		}
		current = child
	}
	return true
}
