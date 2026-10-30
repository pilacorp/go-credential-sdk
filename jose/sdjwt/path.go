// Claim paths, as SD-JWT VC draft 19 §5.6.1 and OpenID4VP 1.0 §7 define
// them, without the null element that selects every array element: a string
// element selects an object property (RFC 9901 §4.2.1), an int element an
// array element (§4.2.2). The Recreated methods count indices in the
// recreated arrays, as a presentation shows them; Type Metadata counts the
// array as issued, read through Issued.

package sdjwt

import (
	"cmp"
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
func (p Path) String() string { return p.format(strconv.Quote) }

// format writes the path as String does, each name written by quote.
func (p Path) format(quote func(string) string) string {
	var b strings.Builder
	b.WriteByte('[')
	for i, el := range p {
		if i > 0 {
			b.WriteByte(',')
		}
		switch v := el.(type) {
		case string:
			b.WriteString(quote(v))
		case int:
			b.WriteString(strconv.Itoa(v))
		default:
			fmt.Fprintf(&b, "%T", el)
		}
	}
	b.WriteByte(']')
	return b.String()
}

// compare orders valid paths longer first, then element by element: a name
// before an index, names by bytes, indices by value. It is 0 only for equal
// paths, and it allocates nothing, so sorting paths costs no more than reading
// them.
func (p Path) compare(q Path) int {
	if len(p) != len(q) {
		return len(q) - len(p)
	}
	for i := range p {
		a, aName := p[i].(string)
		b, bName := q[i].(string)
		switch {
		case aName && bName:
			if c := strings.Compare(a, b); c != 0 {
				return c
			}
		case aName:
			return -1
		case bName:
			return 1
		default:
			if c := cmp.Compare(p[i].(int), q[i].(int)); c != 0 {
				return c
			}
		}
	}
	return 0
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
