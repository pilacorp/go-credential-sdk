// Strict JSON for JOSE headers and claims: RFC 8259, RFC 7515 §10.12.

package jose

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/pilacorp/go-credential-sdk/jose/internal/errtext"
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

// DecodeJSONStringMember returns the top-level member name of the JSON object
// in data, which must be a string, and whether it is present, without
// building any other value: the other members are only scanned as JSON, and a
// member name of another type is refused unread. It lets a caller read one
// string claim of a payload it has not verified yet, such as iss to find the
// key, at the cost of a scan instead of a decode.
//
// It follows DecodeJSON on what it reads: valid UTF-8, one object and nothing
// after it but whitespace, and keys compared after unescaping, so a name
// present twice, spelled the same way or not, is ErrMalformed. A member name
// that is not a string is ErrMalformed too. Duplicate keys and nesting depth
// inside the other members are left to DecodeJSON, which may still refuse
// data this accepts.
func DecodeJSONStringMember(data []byte, name string) (string, bool, error) {
	if !utf8.Valid(data) {
		return "", false, fmt.Errorf("%w: JSON is not valid UTF-8", ErrMalformed)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return "", false, fmt.Errorf("%w: JSON value is not an object", ErrMalformed)
	}
	var member json.RawMessage
	found := false
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return "", false, fmt.Errorf("%w: JSON: %v", ErrMalformed, err)
		}
		key, _ := tok.(string) // the decoder yields only strings as keys
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return "", false, fmt.Errorf("%w: JSON: %v", ErrMalformed, err)
		}
		if key != name {
			continue
		}
		if found {
			return "", false, fmt.Errorf("%w: JSON: duplicate key %s", ErrMalformed, errtext.Quote(name))
		}
		member, found = raw, true
	}
	if _, err := dec.Token(); err != nil { // '}'
		return "", false, fmt.Errorf("%w: JSON: %v", ErrMalformed, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return "", false, fmt.Errorf("%w: JSON: data after the value", ErrMalformed)
	}
	if !found {
		return "", false, nil
	}
	// The scan proved member is one JSON value, so its first byte names its
	// type. Only a string is decoded: anything else could be a megabyte of
	// small values, built for nothing.
	if member[0] != '"' {
		return "", false, fmt.Errorf("%w: JSON: member %s is %s, not a string", ErrMalformed, errtext.Quote(name), jsonKind(member[0]))
	}
	v, err := DecodeJSON(member)
	if err != nil {
		return "", false, err
	}
	s, _ := v.(string) // a value starting with '"' decodes to a string
	return s, true, nil
}

// jsonKind names the type of the JSON value that starts with c.
func jsonKind(c byte) string {
	switch c {
	case '{':
		return "an object"
	case '[':
		return "an array"
	case 't', 'f':
		return "a boolean"
	case 'n':
		return "null"
	default:
		return "a number"
	}
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
				return nil, fmt.Errorf("duplicate key %s", errtext.Quote(key))
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
