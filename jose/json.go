// Strict JSON for JOSE headers and claims: RFC 8259, RFC 7515 §10.12.

package jose

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf16"
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
// in data, which must be a string, and whether it is present, building no
// other value. It lets a caller read one string claim of a payload it has not
// verified yet, such as iss to find the key. It reads data three times:
// utf8.Valid, json.Valid, then a walk over the top-level members that
// compares each key to name in place, so it makes a few allocations however
// many members data holds. Only the member name is decoded, and only when it
// is a string; one of another type is refused unread.
//
// It follows DecodeJSON on what it reads: valid UTF-8, one object and nothing
// after it but whitespace, and keys compared after unescaping, so a name
// present twice, spelled the same way or not, is ErrMalformed. A member name
// that is not a string is ErrMalformed too. json.Valid applies
// encoding/json's limit of 10000 nesting levels counted from the top-level
// object, so a member nested 10000 levels deep is ErrMalformed here.
// Duplicate keys inside the other members and MaxJSONDepth are left to
// DecodeJSON, which may still refuse data this accepts.
func DecodeJSONStringMember(data []byte, name string) (string, bool, error) {
	if !utf8.Valid(data) {
		return "", false, fmt.Errorf("%w: JSON is not valid UTF-8", ErrMalformed)
	}
	if !json.Valid(data) {
		// Unmarshal runs the same syntax check first and returns its error
		// before decoding anything.
		var v any
		err := json.Unmarshal(data, &v)
		return "", false, fmt.Errorf("%w: JSON: %v", ErrMalformed, err)
	}
	// data is now one valid JSON value, so the walk needs no checks of its
	// own: strings close, brackets match, and a ':' follows every key.
	i := skipJSONSpace(data, 0)
	if data[i] != '{' {
		return "", false, fmt.Errorf("%w: JSON value is not an object", ErrMalformed)
	}
	var member []byte
	found := false
	for i = skipJSONSpace(data, i+1); data[i] != '}'; {
		keyEnd := endJSONString(data, i)
		isName := jsonStringIs(data[i+1:keyEnd-1], name)
		i = skipJSONSpace(data, skipJSONSpace(data, keyEnd)+1)
		end := endJSONValue(data, i)
		if isName {
			if found {
				return "", false, fmt.Errorf("%w: JSON: duplicate key %s", ErrMalformed, errtext.Quote(name))
			}
			member, found = data[i:end], true
		}
		if i = skipJSONSpace(data, end); data[i] == ',' {
			i = skipJSONSpace(data, i+1)
		}
	}
	if !found {
		return "", false, nil
	}
	// Only a string is decoded: anything else could be a megabyte of small
	// values, built for nothing.
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

// The helpers below walk JSON that json.Valid accepted; on other input they
// may panic.

// skipJSONSpace returns the index of the first byte at or after i that is
// not JSON whitespace (RFC 8259 §2).
func skipJSONSpace(data []byte, i int) int {
	for i < len(data) && isJSONSpace(data[i]) {
		i++
	}
	return i
}

func isJSONSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

// endJSONString returns the index just after the string starting at data[i].
func endJSONString(data []byte, i int) int {
	for j := i + 1; ; j++ {
		switch data[j] {
		case '\\':
			j++ // the escaped byte never closes the string
		case '"':
			return j + 1
		}
	}
}

// endJSONValue returns the index just after the value starting at data[i].
func endJSONValue(data []byte, i int) int {
	switch data[i] {
	case '"':
		return endJSONString(data, i)
	case '{', '[':
		depth := 0
		for j := i; ; j++ {
			switch data[j] {
			case '"':
				j = endJSONString(data, j) - 1
			case '{', '[':
				depth++
			case '}', ']':
				if depth--; depth == 0 {
					return j + 1
				}
			}
		}
	default: // a number, true, false or null, which ends at a delimiter
		j := i
		for j < len(data) && data[j] != ',' && data[j] != '}' && data[j] != ']' && !isJSONSpace(data[j]) {
			j++
		}
		return j
	}
}

// jsonStringIs reports whether the body of a JSON string, s without its
// quotes, unescapes to name under encoding/json's rules, where an escaped
// surrogate that is not half of a pair reads as U+FFFD. It builds nothing.
func jsonStringIs(s []byte, name string) bool {
	if bytes.IndexByte(s, '\\') < 0 {
		return string(s) == name
	}
	var buf [utf8.UTFMax]byte
	for len(s) > 0 {
		var out []byte
		switch {
		case s[0] != '\\':
			out, s = s[:1], s[1:]
		case s[1] != 'u':
			buf[0] = jsonUnescape(s[1])
			out, s = buf[:1], s[2:]
		default:
			r := hex4(s[2:6])
			s = s[6:]
			if utf16.IsSurrogate(r) {
				next := rune(-1)
				if len(s) >= 6 && s[0] == '\\' && s[1] == 'u' {
					next = hex4(s[2:6])
				}
				if pair := utf16.DecodeRune(r, next); pair != utf8.RuneError {
					r, s = pair, s[6:]
				} else {
					r = utf8.RuneError
				}
			}
			out = buf[:utf8.EncodeRune(buf[:], r)]
		}
		if len(out) > len(name) || string(out) != name[:len(out)] {
			return false
		}
		name = name[len(out):]
	}
	return name == ""
}

// jsonUnescape returns the byte the one-letter escape \c stands for.
func jsonUnescape(c byte) byte {
	switch c {
	case 'b':
		return '\b'
	case 'f':
		return '\f'
	case 'n':
		return '\n'
	case 'r':
		return '\r'
	case 't':
		return '\t'
	default: // '"', '\\' and '/'
		return c
	}
}

// hex4 reads the four hex digits of a \u escape.
func hex4(h []byte) rune {
	var r rune
	for _, c := range h[:4] {
		switch {
		case c <= '9':
			c -= '0'
		case c >= 'a':
			c -= 'a' - 10
		default:
			c -= 'A' - 10
		}
		r = r<<4 | rune(c)
	}
	return r
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
// none of them escaped) and with UTF-8 kept as is (RFC 8259 §8.1), except
// U+2028 and U+2029, which encoding/json always writes as \u2028 and \u2029;
// invalid UTF-8 in strings and keys becomes U+FFFD, as in encoding/json, so
// keys that become equal once each invalid byte is replaced by U+FFFD (such
// as "a\xff" and "a\xfe", or "\xff" and "\ufffd") come out as one key twice,
// which DecodeJSON refuses as a duplicate. Map keys come out sorted, so the same
// value always gives the same bytes. A value encoding/json cannot encode (a
// channel, a function, NaN) is ErrInvalidArgument.
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
