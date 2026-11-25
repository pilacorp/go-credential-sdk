package jsoncanonicalizer

import "testing"

// TestLoneSurrogatesRefused checks RFC 8785 §3.2.2.2: a lone surrogate must end
// canonicalization with an error, never be replaced by U+FFFD. A replacement
// would give different inputs the same canonical form, and so the same signature.
func TestLoneSurrogatesRefused(t *testing.T) {
	for _, input := range []string{
		"[\"\\uD800\"]",        // high surrogate at the end of the string
		"[\"\\uD800x\"]",       // high surrogate followed by a plain character
		"[\"\\uD800\\u0041\"]", // high surrogate followed by a non-surrogate escape
		"[\"\\uD800\\uD800\"]", // two high surrogates
		"[\"\\uDC00\"]",        // low surrogate alone
		"[\"\\uDC00\\uDC00\"]", // two low surrogates
		"[\"\\uDFFF\\uD800\"]", // low before high
		"{\"\\uDC00\":1}",      // lone surrogate in a member name
	} {
		if out, err := Transform([]byte(input)); err == nil {
			t.Errorf("Transform(%s) = %q, want error", input, out)
		}
	}
}

func TestSurrogatePairAccepted(t *testing.T) {
	got, err := Transform([]byte("[\"\\uD83D\\uDE00\",\"\\uDBFF\\uDFFF\"]"))
	if err != nil {
		t.Fatalf("Transform: %v", err)
	}
	if want := "[\"\xf0\x9f\x98\x80\",\"\xf4\x8f\xbf\xbf\"]"; string(got) != want {
		t.Errorf("Transform = %q, want %q", got, want)
	}
}

// TestInvalidUTF8Refused checks RFC 8785 §3.1: string data must be Unicode.
func TestInvalidUTF8Refused(t *testing.T) {
	for _, input := range []string{
		"[\"\xff\"]",              // byte that never starts UTF-8
		"[\"\xc3\"]",              // truncated two-byte sequence
		"[\"\xc0\xaf\"]",          // overlong encoding of '/'
		"[\"\xed\xa0\x80\"]",      // UTF-8 encoded surrogate
		"[\"\xf4\x90\x80\x80\"]",  // above U+10FFFF
		"{\"\xff\":1,\"\xfe\":2}", // invalid member names
	} {
		if out, err := Transform([]byte(input)); err == nil {
			t.Errorf("Transform(%q) = %q, want error", input, out)
		}
	}
}
