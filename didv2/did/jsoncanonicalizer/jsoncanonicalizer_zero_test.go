package jsoncanonicalizer

import "testing"

// TestNegativeZeroRefused checks RFC 8785 §5 as corrected by erratum 7920:
// -0 would be serialized as 0, so it is refused instead.
func TestNegativeZeroRefused(t *testing.T) {
	for _, input := range []string{`[-0]`, `[-0.0]`, `[-0e10]`, `[-0E-5]`, `[-1e-400]`, `{"v":-0}`} {
		if out, err := Transform([]byte(input)); err == nil {
			t.Errorf("Transform(%s) = %s, want error", input, out)
		}
	}
	for _, tt := range []struct{ input, want string }{
		{`[0]`, `[0]`},
		{`[0.0]`, `[0]`},
		{`[0e10]`, `[0]`},
		{`[-0.5]`, `[-0.5]`},
	} {
		got, err := Transform([]byte(tt.input))
		if err != nil || string(got) != tt.want {
			t.Errorf("Transform(%s) = %s, %v; want %s", tt.input, got, err, tt.want)
		}
	}
}
