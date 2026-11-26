package jsonmap

import (
	"testing"
)

// A "~" not followed by 0 or 1 is refused (RFC 6901 §3); main read "~2"
// literally as part of the key.
func TestSelectJSONLDRejectsBadTildeEscape(t *testing.T) {
	doc := map[string]interface{}{
		"foo~2bar": "oops",
		"name":     "Alice",
	}
	_, err := SelectJSONLD(doc, []string{"/foo~2bar"})
	if err == nil {
		t.Fatal(`SelectJSONLD("/foo~2bar") = nil error; want bad-escape error`)
	}
}
