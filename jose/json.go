package jose

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

// MaxJSONDepth is the deepest nesting of objects and arrays DecodeJSON
// accepts. Real headers, payloads and disclosures stay far below it.
const MaxJSONDepth = 64

// DecodeJSON parses data as exactly one JSON value, under the rules every
// header, payload and disclosure is read with:
//   - a duplicate key, at any depth, is rejected. encoding/json keeps the last
//     one silently, which would let two parties read different values (two
//     _sd arrays) from one object; RFC 7519 allows rejecting. Keys are compared
//     after unescaping, so "a" and "\u0061" are the same key;
//   - numbers are kept as json.Number, so large integers keep every digit;
//   - anything after the value but whitespace is rejected;
//   - the input must be valid UTF-8 (RFC 8259); encoding/json would replace
//     invalid bytes with U+FFFD silently;
//   - objects and arrays nest at most MaxJSONDepth deep. The check runs while
//     reading, so a megabyte of "[[[[" is refused at the first level past the
//     limit instead of being decoded into hundreds of megabytes first.
//
// Objects come back as map[string]any, arrays as []any (never nil).
func DecodeJSON(data []byte) (any, error) {
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("%w: JSON is not valid UTF-8", ErrMalformed)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	v, err := readJSONValue(dec, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: JSON: %v", ErrMalformed, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: JSON: data after the value", ErrMalformed)
	}
	return v, nil
}

// DecodeJSONObject is DecodeJSON for a value that must be an object.
func DecodeJSONObject(data []byte) (map[string]any, error) {
	v, err := DecodeJSON(data)
	if err != nil {
		return nil, err
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: JSON value is not an object", ErrMalformed)
	}
	return obj, nil
}

// EncodeJSON encodes v compactly, without HTML escaping (encoding/json turns
// <, > and & into \u003c, \u003e and \u0026 by default) and with UTF-8 kept
// as is. Map keys come out sorted, so the same value always gives the same
// bytes.
func EncodeJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

func readJSONValue(dec *json.Decoder, depth int) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return tok, nil // string, json.Number, bool or nil
	}
	if depth >= MaxJSONDepth {
		return nil, fmt.Errorf("nesting deeper than %d", MaxJSONDepth)
	}
	switch delim {
	case '{':
		obj := map[string]any{}
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyTok.(string)
			if !ok {
				return nil, fmt.Errorf("object key is not a string")
			}
			if _, dup := obj[key]; dup {
				return nil, fmt.Errorf("duplicate key %q", key)
			}
			val, err := readJSONValue(dec, depth+1)
			if err != nil {
				return nil, err
			}
			obj[key] = val
		}
		if _, err := dec.Token(); err != nil { // '}'
			return nil, err
		}
		return obj, nil
	case '[':
		arr := []any{}
		for dec.More() {
			val, err := readJSONValue(dec, depth+1)
			if err != nil {
				return nil, err
			}
			arr = append(arr, val)
		}
		if _, err := dec.Token(); err != nil { // ']'
			return nil, err
		}
		return arr, nil
	default:
		return nil, fmt.Errorf("unexpected %q", delim)
	}
}
