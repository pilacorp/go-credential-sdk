// Strict JSON for JOSE headers and claims: RFC 8259, RFC 7515 §10.12.

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
// accepts (RFC 8259 §9: a parser may limit nesting depth). Real headers,
// payloads and disclosures stay far below it.
const MaxJSONDepth = 64

// DecodeJSON parses data as exactly one JSON value, under the rules every
// header, payload and disclosure is read with:
//   - a duplicate key, at any depth, is rejected (see readJSONValue).
//     encoding/json keeps the last one silently, which would let two parties
//     read different values (two _sd arrays) from one object. Keys are
//     compared after unescaping, so "a" and "\u0061" are the same key;
//   - numbers are kept as json.Number, so large integers keep every digit
//     (RFC 8259 §6 leaves range and precision to the implementation);
//   - anything after the value but whitespace is rejected;
//   - the input must be valid UTF-8; encoding/json would replace invalid
//     bytes with U+FFFD silently;
//   - objects and arrays nest at most MaxJSONDepth deep. The check runs while
//     reading, so a megabyte of "[[[[" is refused at the first level past the
//     limit instead of being decoded into hundreds of megabytes first.
//
// Objects come back as map[string]any, arrays as []any (never nil).
func DecodeJSON(data []byte) (any, error) {
	// RFC 8259 §8.1, RFC 7515 §5.2 step 3 and RFC 8725 §3.7: UTF-8 only.
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("%w: JSON is not valid UTF-8", ErrMalformed)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	v, err := readJSONValue(dec, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: JSON: %v", ErrMalformed, err)
	}
	// RFC 7515 §10.12: input with extra significant characters after a valid
	// JSON value MUST be considered invalid.
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
// <, > and & into \u003c, \u003e and \u0026 by default; RFC 8259 §7 needs
// none of them escaped) and with UTF-8 kept as is (RFC 8259 §8.1). Map keys
// come out sorted, so the same value always gives the same bytes. A value
// encoding/json cannot encode (a channel, a function, NaN) is
// ErrInvalidArgument.
func EncodeJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, fmt.Errorf("%w: encode JSON: %w", ErrInvalidArgument, err)
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
			// RFC 7515 §4 (header) and RFC 7519 §4 (claims): names MUST be
			// unique and parsers MUST either reject duplicates or keep the
			// lexically last; this package rejects. Below the top level, RFC
			// 8259 §4 says SHOULD, and RFC 7515 §10.12 treats such ambiguity as
			// exploitable, so nested duplicates are rejected too. Keys are
			// compared after unescaping (RFC 8259 §8.3, RFC 7515 §10.13), so
			// "alg" and "\u0061lg" are duplicates.
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
