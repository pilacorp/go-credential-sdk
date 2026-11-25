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

// This package transforms JSON data in UTF-8 according to:
// https://tools.ietf.org/html/draft-rundgren-json-canonicalization-scheme-02

// TODO: This package is written by owner of RFC 8785, consider to replace with json/v2
// when go 1.25 is released
package jsoncanonicalizer

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode/utf16"
)

type nameValueType struct {
	name    string
	sortKey []uint16
	value   jsonValue
}

type valueKind int

const (
	kindScalar valueKind = iota
	kindArray
	kindObject
)

// jsonValue is one parsed value. A scalar holds its canonical text; arrays and
// objects hold their children, so the output is written in a single pass.
type jsonValue struct {
	kind     valueKind
	scalar   string
	elements []jsonValue
	members  []nameValueType
}

// JSON standard escapes (modulo \u)
var asciiEscapes = []byte{'\\', '"', 'b', 'f', 'n', 'r', 't'}
var binaryEscapes = []byte{'\\', '"', '\b', '\f', '\n', '\r', '\t'}

// JSON literals
var literals = []string{"true", "false", "null"}

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
			setError("Expected '" + string(expected) + "' but got '" + string(c) + "'")
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
						// If the first UTF-16 code unit has a certain value there must be
						// another succeeding UTF-16 code unit as well
						if nextChar() != '\\' || nextChar() != 'u' {
							setError("Missing surrogate")
						} else {
							// Output the UTF-32 code point as UTF-8
							rawString.WriteRune(utf16.DecodeRune(firstUTF16, getUEscape()))
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
					setError("Unexpected escape: \\" + string(c))
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
			setError("Invalid JSON number: " + value)
			return jsonValue{}
		}
		ieeeF64, err := strconv.ParseFloat(value, 64)
		checkError(err)
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

	parseArray = func() jsonValue {
		array := jsonValue{kind: kindArray}
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
		return array
	}

	parseObject = func() jsonValue {
		object := jsonValue{kind: kindObject}
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
			// Sort keys on UTF-16 code units
			// Since UTF-8 doesn't have endianess this is just a value transformation
			// In the Go case the transformation is UTF-8 => UTF-32 => UTF-16
			sortKey := utf16.Encode([]rune(rawUTF8))
			scanFor(':')
			object.members = append(object.members, nameValueType{rawUTF8, sortKey, parseElement()})
		}
		// Scan away '}'
		scan()
		if globalError != nil {
			return object
		}
		// RFC 8785 §3.2.3: members are ordered by their names as arrays of UTF-16
		// code units compared as unsigned integers, a shorter prefix first, which
		// is exactly what slices.Compare does on []uint16.
		slices.SortFunc(object.members, func(a, b nameValueType) int {
			return slices.Compare(a.sortKey, b.sortKey)
		})
		for i := 1; i < len(object.members); i++ {
			if slices.Equal(object.members[i-1].sortKey, object.members[i].sortKey) {
				setError("Duplicate key: " + object.members[i].name)
				break
			}
		}
		return object
	}

	// The output is written once, after parsing: building it level by level
	// copied every nested value once per enclosing level.
	var canonical strings.Builder
	var writeValue func(v jsonValue)
	writeValue = func(v jsonValue) {
		switch v.kind {
		case kindArray:
			canonical.WriteByte('[')
			for i, element := range v.elements {
				if i > 0 {
					canonical.WriteByte(',')
				}
				writeValue(element)
			}
			canonical.WriteByte(']')
		case kindObject:
			canonical.WriteByte('{')
			for i, member := range v.members {
				if i > 0 {
					canonical.WriteByte(',')
				}
				canonical.WriteString(decorateString(member.name))
				canonical.WriteByte(':')
				writeValue(member.value)
			}
			canonical.WriteByte('}')
		default:
			canonical.WriteString(v.scalar)
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
