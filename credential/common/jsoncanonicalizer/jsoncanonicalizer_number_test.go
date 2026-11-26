package jsoncanonicalizer

import (
	"fmt"
	"testing"
)

// TestInvalidNumberTokensInArray verifies that number tokens not matching
// RFC 8259 §6 grammar are rejected when they appear inside a JSON array.
func TestInvalidNumberTokensInArray(t *testing.T) {
	invalid := []string{
		"01",    // leading zero
		"-01",   // negative leading zero
		"00",    // double zero
		"1.",    // trailing dot
		"+1",    // leading plus
		".5",    // leading dot
		"-",     // bare minus
		"1e",    // incomplete exponent
		"0x1",   // hex literal
		"Inf",   // infinity
		"-Inf",  // negative infinity
		"NaN",   // not a number
		"1_000", // underscore separator
		"1.e1",  // dot without fraction digits before exponent
		"0.",    // trailing dot on zero
		"-.1",   // minus then dot (no integer part)
		"1e+",   // exponent sign without digits
		"1e-",   // exponent sign without digits
	}
	for _, tok := range invalid {
		t.Run(tok, func(t *testing.T) {
			input := fmt.Sprintf("[%s]", tok)
			_, err := Transform([]byte(input))
			if err == nil {
				t.Errorf("Transform(%q) succeeded, want error", input)
			}
		})
	}
}

// TestInvalidNumberTokensInObject verifies that invalid number tokens are
// also rejected when they appear as an object value.
func TestInvalidNumberTokensInObject(t *testing.T) {
	invalid := []string{
		"01",    // leading zero
		"-01",   // negative leading zero
		"00",    // double zero
		"1.",    // trailing dot
		"+1",    // leading plus
		".5",    // leading dot
		"-",     // bare minus
		"1e",    // incomplete exponent
		"0x1",   // hex literal
		"Inf",   // infinity
		"-Inf",  // negative infinity
		"NaN",   // not a number
		"1_000", // underscore separator
		"1.e1",  // dot without fraction digits before exponent
		"0.",    // trailing dot on zero
		"-.1",   // minus then dot (no integer part)
		"1e+",   // exponent sign without digits
		"1e-",   // exponent sign without digits
	}
	for _, tok := range invalid {
		t.Run(tok, func(t *testing.T) {
			input := fmt.Sprintf(`{"n":%s}`, tok)
			_, err := Transform([]byte(input))
			if err == nil {
				t.Errorf("Transform(%q) succeeded, want error", input)
			}
		})
	}
}

// TestValidNumberTokens verifies that valid JSON numbers per RFC 8259 §6
// canonicalize successfully and produce byte-identical output to the
// current behavior (they go through NumberToJSON unchanged in semantics).
func TestValidNumberTokens(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{`[0]`, `[0]`},
		{`[1]`, `[1]`},
		{`[-1]`, `[-1]`},
		{`[1.5]`, `[1.5]`},
		{`[1.5e10]`, `[15000000000]`},
		{`[1E-7]`, `[1e-7]`},
		{`[1e+7]`, `[10000000]`},
		{`[1e0]`, `[1]`},
		{`[1e1]`, `[10]`},
		{`[0.0]`, `[0]`},
		{`[100]`, `[100]`},
		{`[-100]`, `[-100]`},
		{`[0.5]`, `[0.5]`},
		{`[-0.5]`, `[-0.5]`},
		{`[1e-1]`, `[0.1]`},
		{`[1.0e2]`, `[100]`},
		{`[1.23e4]`, `[12300]`},
		{`[1.23e-4]`, `[0.000123]`},
		{`[1234567890]`, `[1234567890]`},
		{`[-1234567890]`, `[-1234567890]`},
		{`[9999999999999999]`, `[10000000000000000]`}, // float64 rounding
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got, err := Transform([]byte(tc.input))
			if err != nil {
				t.Fatalf("Transform(%q) error: %v", tc.input, err)
			}
			if string(got) != tc.want {
				t.Errorf("Transform(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// TestIsValidJSONNumber directly tests the grammar checker against the
// RFC 8259 §6 number production.
func TestIsValidJSONNumber(t *testing.T) {
	cases := []struct {
		input string
		valid bool
	}{
		// Valid
		{"0", true},
		{"-0", true},
		{"1", true},
		{"-1", true},
		{"123", true},
		{"1.5", true},
		{"0.5", true},
		{"-0.5", true},
		{"1e10", true},
		{"1E10", true},
		{"1e+10", true},
		{"1e-10", true},
		{"1.5e10", true},
		{"1.23e-4", true},
		{"100", true},
		{"9999999999999999", true},

		// Invalid
		{"", false},
		{"+1", false},
		{".5", false},
		{"01", false},
		{"-01", false},
		{"00", false},
		{"1.", false},
		{"0.", false},
		{"1.e1", false},
		{"-.1", false},
		{"1e", false},
		{"1e+", false},
		{"1e-", false},
		{"-", false},
		{"1_000", false},
		{"0x1", false},
		{"Inf", false},
		{"NaN", false},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got := isValidJSONNumber(tc.input)
			if got != tc.valid {
				t.Errorf("isValidJSONNumber(%q) = %v, want %v", tc.input, got, tc.valid)
			}
		})
	}
}
