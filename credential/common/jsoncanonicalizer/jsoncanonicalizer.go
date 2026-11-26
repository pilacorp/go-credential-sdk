//
//  Copyright 2006-2019 WebPKI.org (http://webpki.org).
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//

// This package transforms JSON data in UTF-8 according to RFC 8785, JSON
// Canonicalization Scheme (JCS): https://www.rfc-editor.org/rfc/rfc8785

// TODO: encoding/json/jsontext Value.Canonicalize implements RFC 8785 too;
// consider it once Go builds it without GOEXPERIMENT=jsonv2 (still needed in Go 1.27).
package jsoncanonicalizer

import (
	"cmp"
	"errors"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

type nameValueType struct {
	name  string
	value jsonValue
}

// jsonValue is one parsed value: a scalar holds its canonical text, an array or
// object its children, so the output is written in a single pass. It is kept to
// three words because one exists for every array element.
type jsonValue struct {
	scalar    string
	container *jsonContainer
}

type jsonContainer struct {
	isObject bool
	elements []jsonValue
	members  []nameValueType
}

// compareUTF16 orders two valid UTF-8 strings by their UTF-16 code units, as
// RFC 8785 §3.2.3 requires. Code point order differs from it only where a code
// point above U+FFFF (a surrogate pair) meets one in U+E000-U+FFFF.
func compareUTF16(a, b string) int {
	for a != "" && b != "" {
		ra, na := utf8.DecodeRuneInString(a)
		rb, nb := utf8.DecodeRuneInString(b)
		if ra != rb {
			ha, la := utf16Units(ra)
			hb, lb := utf16Units(rb)
			if c := cmp.Compare(ha, hb); c != 0 {
				return c
			}
			return cmp.Compare(la, lb)
		}
		a, b = a[na:], b[nb:]
	}
	return cmp.Compare(len(a), len(b))
}

// utf16Units returns the first and second UTF-16 code unit of r; the second is
// zero for a code point that needs one unit.
func utf16Units(r rune) (uint16, uint16) {
	if r1, r2 := utf16.EncodeRune(r); r1 != utf8.RuneError {
		return uint16(r1), uint16(r2)
	}
	return uint16(r), 0
}

// JSON standard escapes (modulo \u)
var asciiEscapes = []byte{'\\', '"', 'b', 'f', 'n', 'r', 't'}
var binaryEscapes = []byte{'\\', '"', '\b', '\f', '\n', '\r', '\t'}

// JSON literals
var literals = []string{"true", "false", "null"}

// maxNestingDepth bounds how deeply arrays and objects may nest. Parsing and
// writing recurse once per level and Go cannot recover from a stack overflow.
// RFC 8259 §9 lets a parser limit nesting; encoding/json stops at the same depth.
const maxNestingDepth = 10000

// isValidJSONNumber checks whether s matches the RFC 8259 §6 number grammar:
//
//	number = [ "-" ] int [ frac ] [ exp ]
//	int    = "0" / ( digit1-9 *DIGIT )
//	frac   = "." 1*DIGIT
//	exp    = ("e" / "E") [ "+" / "-" ] 1*DIGIT
func isValidJSONNumber(s string) bool {
	if len(s) == 0 {
		return false
	}
	i := 0

	// Optional leading minus
	if s[i] == '-' {
		i++
		if i == len(s) {
			return false
		}
	}

	// Integer part: "0" or digit1-9 followed by digits
	if s[i] == '0' {
		i++
		// After a leading 0 the next character must not be a digit (no 01, 00, etc.)
		if i < len(s) && s[i] >= '0' && s[i] <= '9' {
			return false
		}
	} else if s[i] >= '1' && s[i] <= '9' {
		i++
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
		}
	} else {
		return false // must start with digit
	}

	// Optional fraction
	if i < len(s) && s[i] == '.' {
		i++
		if i == len(s) || s[i] < '0' || s[i] > '9' {
			return false // at least one digit after dot
		}
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
		}
	}

	// Optional exponent
	if i < len(s) && (s[i] == 'e' || s[i] == 'E') {
		i++
		if i == len(s) {
			return false
		}
		if s[i] == '+' || s[i] == '-' {
			i++
		}
		if i == len(s) || s[i] < '0' || s[i] > '9' {
			return false // at least one digit in exponent
		}
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
		}
	}

	return i == len(s)
}

// errorExcerpt quotes a token for an error message and cuts it short: the
// input may come from outside, and a long token would end up whole in logs.
func errorExcerpt(token string) string {
	const maxLen = 32
	if len(token) > maxLen {
		return strconv.Quote(token[:maxLen]) + "..."
	}
	return strconv.Quote(token)
}

// Transform canonicalizes JSON data according to RFC 8785 (JSON Canonicalization Scheme).
//
// Canonicalization ensures that semantically equivalent JSON documents produce
// identical byte sequences, enabling consistent hashing and digital signatures.
// This is critical for DID Document hashing, where the same document must always
// produce the same hash regardless of formatting differences.
//
// The transformation process:
//   - Removes all whitespace
//   - Sorts object members by their names as UTF-16 code units (RFC 8785 §3.2.3)
//   - Serializes numbers as ECMAScript does (RFC 8785 §3.2.2.3)
//   - Writes strings in their shortest escaped form (RFC 8785 §3.2.2.2)
//   - Writes the literals null, true and false as they are
//
// The jsonData parameter is UTF-8 encoded JSON whose top-level value is an object
// or an array. Non-ASCII characters are accepted inside strings only.
//
// Transform returns a nil slice and an error if:
//   - The input is not valid JSON
//   - A string holds a lone surrogate or bytes that are not UTF-8 (RFC 8785 §3.1, §3.2.2.2)
//   - An object has two members with the same name (RFC 8785 §3.1)
//   - A number is too large for an IEEE 754 double, so it would be Infinity (RFC 8785 §3.2.2.3)
//   - A number is negative zero (RFC 8785 §5, erratum 7920)
//   - Arrays and objects nest deeper than 10000 levels (RFC 8259 §9 allows the limit)
//
// Example use case: Hashing DID Documents for blockchain transactions.
func Transform(jsonData []byte) (result []byte, e error) {

	// JSON data MUST be UTF-8 encoded
	var jsonDataLength int = len(jsonData)

	// Current pointer in jsonData
	var index int = 0

	// "Forward" declarations are needed for closures referring each other
	var parseElement func() jsonValue
	var parseSimpleType func() jsonValue
	var parseQuotedString func() string
	var parseObject func() jsonValue
	var parseArray func() jsonValue

	var globalError error = nil

	// Current nesting depth of arrays and objects
	var depth int = 0

	checkError := func(e error) {
		// We only honor the first reported error
		if globalError == nil {
			globalError = e
		}
	}

	setError := func(msg string) {
		checkError(errors.New(msg))
	}

	isWhiteSpace := func(c byte) bool {
		return c == 0x20 || c == 0x0a || c == 0x0d || c == 0x09
	}

	nextChar := func() byte {
		if index < jsonDataLength {
			c := jsonData[index]
			if c > 0x7f {
				setError("Unexpected non-ASCII character")
			}
			index++
			return c
		}
		setError("Unexpected EOF reached")
		return '"'
	}

	scan := func() byte {
		for {
			c := nextChar()
			if isWhiteSpace(c) {
				continue
			}
			return c
		}
	}

	scanFor := func(expected byte) {
		c := scan()
		if c != expected {
			setError("Expected '" + string(expected) + "' but got " + errorExcerpt(string([]byte{c})))
		}
	}

	getUEscape := func() rune {
		start := index
		nextChar()
		nextChar()
		nextChar()
		nextChar()
		if globalError != nil {
			return 0
		}
		u16, err := strconv.ParseUint(string(jsonData[start:index]), 16, 64)
		checkError(err)
		return rune(u16)
	}

	testNextNonWhiteSpaceChar := func() byte {
		save := index
		c := scan()
		index = save
		return c
	}

	decorateString := func(rawUTF8 string) string {
		var quotedString strings.Builder
		quotedString.WriteByte('"')
	CoreLoop:
		for _, c := range []byte(rawUTF8) {
			// Is this within the JSON standard escapes?
			for i, esc := range binaryEscapes {
				if esc == c {
					quotedString.WriteByte('\\')
					quotedString.WriteByte(asciiEscapes[i])
					continue CoreLoop
				}
			}
			if c < 0x20 {
				// Other ASCII control characters must be escaped with \uhhhh
				quotedString.WriteString(fmt.Sprintf("\\u%04x", c))
			} else {
				quotedString.WriteByte(c)
			}
		}
		quotedString.WriteByte('"')
		return quotedString.String()
	}

	parseQuotedString = func() string {
		var rawString strings.Builder
	CoreLoop:
		for globalError == nil {
			var c byte
			if index < jsonDataLength {
				c = jsonData[index]
				index++
			} else {
				nextChar()
				break
			}
			if c == '"' {
				break
			}
			if c < ' ' {
				setError("Unterminated string literal")
			} else if c == '\\' {
				// Escape sequence
				c = nextChar()
				if c == 'u' {
					// The \u escape
					firstUTF16 := getUEscape()
					if utf16.IsSurrogate(firstUTF16) {
						// RFC 8785 §3.2.2.2: a lone surrogate MUST end canonicalization
						// with an error. Only a high surrogate followed by a low one is a
						// code point; DecodeRune returns RuneError for any other pair.
						if nextChar() != '\\' || nextChar() != 'u' {
							setError("Lone surrogate in string")
						} else if r := utf16.DecodeRune(firstUTF16, getUEscape()); r == utf8.RuneError {
							setError("Lone surrogate in string")
						} else {
							rawString.WriteRune(r)
						}
					} else {
						// Single UTF-16 code identical to UTF-32.  Output as UTF-8
						rawString.WriteRune(firstUTF16)
					}
				} else if c == '/' {
					// Benign but useless escape
					rawString.WriteByte('/')
				} else {
					// The JSON standard escapes
					for i, esc := range asciiEscapes {
						if esc == c {
							rawString.WriteByte(binaryEscapes[i])
							continue CoreLoop
						}
					}
					setError("Unexpected escape: " + errorExcerpt(string([]byte{'\\', c})))
				}
			} else {
				// Just an ordinary ASCII character alternatively a UTF-8 byte
				// outside of ASCII.
				// Note that properly formatted UTF-8 never clashes with ASCII
				// making byte per byte search for ASCII break characters work
				// as expected.
				rawString.WriteByte(c)
			}
		}
		// RFC 8785 §3.1: string data must be Unicode. Raw bytes are copied as
		// they are, so a byte sequence that is not UTF-8 is refused here.
		if globalError == nil && !utf8.ValidString(rawString.String()) {
			setError("Invalid UTF-8 in string")
		}
		return rawString.String()
	}

	parseSimpleType = func() jsonValue {
		var token strings.Builder
		index--
		for globalError == nil {
			c := testNextNonWhiteSpaceChar()
			if c == ',' || c == ']' || c == '}' {
				break
			}
			c = nextChar()
			if isWhiteSpace(c) {
				break
			}
			token.WriteByte(c)
		}
		if token.Len() == 0 {
			setError("Missing argument")
		}
		value := token.String()
		// Is it a JSON literal?
		for _, literal := range literals {
			if literal == value {
				return jsonValue{scalar: literal}
			}
		}
		// Validate that the token is a valid JSON number per RFC 8259 §6
		// before parsing. strconv.ParseFloat accepts forms like "01", "1.",
		// "+1", ".5" that are not valid JSON.
		if !isValidJSONNumber(value) {
			setError("Invalid JSON number: " + errorExcerpt(value))
			return jsonValue{}
		}
		ieeeF64, err := strconv.ParseFloat(value, 64)
		if err != nil {
			// RFC 8785 §3.2.2.3: Infinity MUST end canonicalization with an error.
			// The grammar check above leaves only this overflow error here.
			setError("JSON number out of IEEE 754 range: " + errorExcerpt(value))
			return jsonValue{}
		}
		// RFC 8785 §5 (erratum 7920): -0 is serialized as 0, so a parser SHOULD
		// refuse it rather than let it share a canonical form with 0.
		if ieeeF64 == 0 && math.Signbit(ieeeF64) {
			setError("Negative zero is not allowed: " + errorExcerpt(value))
			return jsonValue{}
		}
		value, err = NumberToJSON(ieeeF64)
		checkError(err)
		return jsonValue{scalar: value}
	}

	parseElement = func() jsonValue {
		switch scan() {
		case '{':
			return parseObject()
		case '"':
			return jsonValue{scalar: decorateString(parseQuotedString())}
		case '[':
			return parseArray()
		default:
			return parseSimpleType()
		}
	}

	enterNesting := func() bool {
		depth++
		if depth > maxNestingDepth {
			setError("Nesting deeper than " + strconv.Itoa(maxNestingDepth) + " levels")
			return false
		}
		return true
	}

	parseArray = func() jsonValue {
		defer func() { depth-- }()
		if !enterNesting() {
			return jsonValue{}
		}
		array := &jsonContainer{}
		var next bool = false
		for globalError == nil && testNextNonWhiteSpaceChar() != ']' {
			if next {
				scanFor(',')
			} else {
				next = true
			}
			array.elements = append(array.elements, parseElement())
		}
		scan()
		return jsonValue{container: array}
	}

	parseObject = func() jsonValue {
		defer func() { depth-- }()
		if !enterNesting() {
			return jsonValue{}
		}
		object := &jsonContainer{isObject: true}
		var next bool = false
		for globalError == nil && testNextNonWhiteSpaceChar() != '}' {
			if next {
				scanFor(',')
			}
			next = true
			scanFor('"')
			rawUTF8 := parseQuotedString()
			if globalError != nil {
				break
			}
			scanFor(':')
			object.members = append(object.members, nameValueType{rawUTF8, parseElement()})
		}
		// Scan away '}'
		scan()
		if globalError != nil {
			return jsonValue{container: object}
		}
		slices.SortFunc(object.members, func(a, b nameValueType) int {
			return compareUTF16(a.name, b.name)
		})
		// Names are valid UTF-8 here, so equal bytes means equal names.
		for i := 1; i < len(object.members); i++ {
			if object.members[i-1].name == object.members[i].name {
				setError("Duplicate key: " + errorExcerpt(object.members[i].name))
				break
			}
		}
		return jsonValue{container: object}
	}

	// The output is written once, after parsing: building it level by level
	// copied every nested value once per enclosing level.
	var canonical strings.Builder
	var writeValue func(v jsonValue)
	writeValue = func(v jsonValue) {
		switch {
		case v.container == nil:
			canonical.WriteString(v.scalar)
		case !v.container.isObject:
			canonical.WriteByte('[')
			for i, element := range v.container.elements {
				if i > 0 {
					canonical.WriteByte(',')
				}
				writeValue(element)
			}
			canonical.WriteByte(']')
		default:
			canonical.WriteByte('{')
			for i, member := range v.container.members {
				if i > 0 {
					canonical.WriteByte(',')
				}
				canonical.WriteString(decorateString(member.name))
				canonical.WriteByte(':')
				writeValue(member.value)
			}
			canonical.WriteByte('}')
		}
	}

	/////////////////////////////////////////////////
	// This is where Transform actually begins...  //
	/////////////////////////////////////////////////
	var root jsonValue

	if testNextNonWhiteSpaceChar() == '[' {
		scan()
		root = parseArray()
	} else {
		scanFor('{')
		root = parseObject()
	}
	for index < jsonDataLength {
		if !isWhiteSpace(jsonData[index]) {
			setError("Improperly terminated JSON object")
			break
		}
		index++
	}
	if globalError != nil {
		return nil, globalError
	}
	writeValue(root)
	return []byte(canonical.String()), nil
}
