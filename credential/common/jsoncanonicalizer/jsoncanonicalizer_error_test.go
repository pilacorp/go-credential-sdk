package jsoncanonicalizer

import (
	"strings"
	"testing"
)

// TestErrorTextBounded checks that a long token from the input is not copied
// whole into the error message.
func TestErrorTextBounded(t *testing.T) {
	long := strings.Repeat("9", 1<<20)
	for _, input := range []string{
		"[" + long + "x]",                     // not a JSON number
		"[" + long + "e999999]",               // out of IEEE 754 range
		`{"` + long + `":1,"` + long + `":2}`, // duplicate member name
	} {
		_, err := Transform([]byte(input))
		if err == nil {
			t.Fatalf("Transform succeeded on a %d-byte input, want error", len(input))
		}
		if len(err.Error()) > 128 {
			t.Errorf("error message is %d bytes, want at most 128", len(err.Error()))
		}
	}
}

// TestNumberOutOfRangeNamed checks that a number an IEEE 754 double cannot hold
// is reported as out of range (RFC 8785 §3.1), not as an invalid token.
func TestNumberOutOfRangeNamed(t *testing.T) {
	_, err := Transform([]byte("[1e400]"))
	if err == nil || !strings.Contains(err.Error(), "out of IEEE 754 range") {
		t.Errorf("Transform([1e400]) error = %v, want an out-of-range error", err)
	}
}

// TestErrorTextQuotesRawBytes checks that a control byte from the input is
// quoted in the error message rather than written raw into logs.
func TestErrorTextQuotesRawBytes(t *testing.T) {
	for _, input := range []string{"{\"a\"\x1b1}", "[\"\\\n\"]"} {
		_, err := Transform([]byte(input))
		if err == nil {
			t.Fatalf("Transform(%q) succeeded, want error", input)
		}
		if strings.ContainsAny(err.Error(), "\x1b\n") {
			t.Errorf("Transform(%q) error %q carries a raw control byte", input, err)
		}
	}
}
