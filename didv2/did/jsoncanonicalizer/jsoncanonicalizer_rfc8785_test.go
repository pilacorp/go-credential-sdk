package jsoncanonicalizer

import (
	"math"
	"testing"
)

// TestRFC8785Examples runs the examples of RFC 8785 §3.2.2 and §3.2.3.
func TestRFC8785Examples(t *testing.T) {
	tests := []struct {
		name, input, want string
	}{
		{
			name:  "§3.2.2 serialization",
			input: `{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001],"string":"\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/","literals":[null,true,false]}`,
			want:  `{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}`,
		},
		{
			name:  "§3.2.3 sorting by UTF-16 code units",
			input: `{"\u20ac":"Euro Sign","\r":"Carriage Return","\ufb33":"Hebrew Letter Dalet With Dagesh","1":"One","\ud83d\ude00":"Emoji: Grinning Face","\u0080":"Control","\u00f6":"Latin Small Letter O With Diaeresis"}`,
			want:  "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u0080\":\"Control\",\"ö\":\"Latin Small Letter O With Diaeresis\",\"€\":\"Euro Sign\",\"😀\":\"Emoji: Grinning Face\",\"" + "\ufb33" + "\":\"Hebrew Letter Dalet With Dagesh\"}",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Transform([]byte(tt.input))
			if err != nil {
				t.Fatalf("Transform: %v", err)
			}
			if string(got) != tt.want {
				t.Errorf("Transform =\n%s\nwant\n%s", got, tt.want)
			}
		})
	}
}

// TestRFC8785NumberSerialization runs the IEEE 754 values of RFC 8785 Appendix B.
func TestRFC8785NumberSerialization(t *testing.T) {
	tests := []struct {
		bits uint64
		want string
	}{
		{0x0000000000000000, "0"},
		{0x8000000000000000, "0"},
		{0x0000000000000001, "5e-324"},
		{0x8000000000000001, "-5e-324"},
		{0x7fefffffffffffff, "1.7976931348623157e+308"},
		{0xffefffffffffffff, "-1.7976931348623157e+308"},
		{0x4340000000000000, "9007199254740992"},
		{0xc340000000000000, "-9007199254740992"},
		{0x4430000000000000, "295147905179352830000"},
		{0x44b52d02c7e14af5, "9.999999999999997e+22"},
		{0x44b52d02c7e14af6, "1e+23"},
		{0x44b52d02c7e14af7, "1.0000000000000001e+23"},
		{0x444b1ae4d6e2ef4e, "999999999999999700000"},
		{0x444b1ae4d6e2ef4f, "999999999999999900000"},
		{0x444b1ae4d6e2ef50, "1e+21"},
		{0x3eb0c6f7a0b5ed8c, "9.999999999999997e-7"},
		{0x3eb0c6f7a0b5ed8d, "0.000001"},
		{0x41b3de4355555553, "333333333.3333332"},
		{0x41b3de4355555554, "333333333.33333325"},
		{0x41b3de4355555555, "333333333.3333333"},
		{0x41b3de4355555556, "333333333.3333334"},
		{0x41b3de4355555557, "333333333.33333343"},
		{0xbecbf647612f3696, "-0.0000033333333333333333"},
		{0x43143ff3c1cb0959, "1424953923781206.2"},
	}
	for _, tt := range tests {
		got, err := NumberToJSON(math.Float64frombits(tt.bits))
		if err != nil || got != tt.want {
			t.Errorf("NumberToJSON(%016x) = %q, %v; want %q", tt.bits, got, err, tt.want)
		}
	}
	for _, bits := range []uint64{0x7fffffffffffffff, 0x7ff0000000000000, 0xfff0000000000000} {
		if _, err := NumberToJSON(math.Float64frombits(bits)); err == nil {
			t.Errorf("NumberToJSON(%016x) succeeded, want error", bits)
		}
	}
}

// TestDuplicateKeysRefused checks RFC 8785 §3.1: objects must not have duplicate
// names, including names that differ only in how they are escaped.
func TestDuplicateKeysRefused(t *testing.T) {
	for _, input := range []string{
		`{"a":1,"a":2}`,
		`{"a":1,"\u0061":2}`,
		`{"b":0,"a":1,"c":{"x":1},"a":2}`,
	} {
		if _, err := Transform([]byte(input)); err == nil {
			t.Errorf("Transform(%s) succeeded, want duplicate key error", input)
		}
	}
}

// TestErrorReturnsNil checks that no partial output comes back with an error.
func TestErrorReturnsNil(t *testing.T) {
	for _, input := range []string{`{"b":1,"a":01}`, `[1,2,`, `{"a":1,"a":2}`} {
		out, err := Transform([]byte(input))
		if err == nil || out != nil {
			t.Errorf("Transform(%s) = %q, %v; want nil and an error", input, out, err)
		}
	}
}
