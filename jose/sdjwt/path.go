package sdjwt

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/pilacorp/go-credential-sdk/jose"
)

// Path points at one claim: a string element selects an object key, an int
// element an array index. Examples: {"given_name"}, {"address", "locality"},
// {"nationalities", 0}. An empty path, a negative index and any other element
// type (float64, json.Number, nil…) are invalid.
type Path []any

func (p Path) validate() error {
	if len(p) == 0 {
		return fmt.Errorf("%w: sdjwt: empty path", jose.ErrInvalidArgument)
	}
	for _, el := range p {
		switch v := el.(type) {
		case string:
		case int:
			if v < 0 {
				return fmt.Errorf("%w: sdjwt: path %s has a negative index", jose.ErrInvalidArgument, p)
			}
		default:
			return fmt.Errorf("%w: sdjwt: path %s has an element of type %T, want string or int", jose.ErrInvalidArgument, p, el)
		}
	}
	return nil
}

// String writes the path as a JSON-like array, e.g. ["nationalities",0].
func (p Path) String() string {
	return "[" + p.key() + "]"
}

// key is a canonical form of the path, used as a map key: quoted strings are
// self-delimiting and indices are bare digits, so distinct paths never share
// a key.
func (p Path) key() string {
	var b strings.Builder
	for i, el := range p {
		if i > 0 {
			b.WriteByte(',')
		}
		switch v := el.(type) {
		case string:
			b.WriteString(strconv.Quote(v))
		case int:
			b.WriteString(strconv.Itoa(v))
		default:
			fmt.Fprintf(&b, "%T(%v)", el, el)
		}
	}
	return b.String()
}

// child returns a new path one element longer that never shares the backing
// array of p, so sibling paths cannot overwrite each other.
func (p Path) child(el any) Path {
	out := make(Path, len(p)+1)
	copy(out, p)
	out[len(p)] = el
	return out
}

// lookup walks v along p and returns the value it points at.
func lookup(v any, p Path) (any, bool) {
	for _, el := range p {
		switch k := el.(type) {
		case string:
			obj, ok := v.(map[string]any)
			if !ok {
				return nil, false
			}
			if v, ok = obj[k]; !ok {
				return nil, false
			}
		case int:
			arr, ok := v.([]any)
			if !ok || k < 0 || k >= len(arr) {
				return nil, false
			}
			v = arr[k]
		default:
			return nil, false
		}
	}
	return v, true
}
