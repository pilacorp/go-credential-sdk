package jose

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestDecodeJSONRejectsDuplicateKeys(t *testing.T) {
	for name, in := range map[string]string{
		"top level":        `{"_sd":["a"],"_sd":["b"]}`,
		"nested object":    `{"a":{"x":1,"x":2}}`,
		"inside an array":  `{"a":[{"x":1,"x":2}]}`,
		"escaped spelling": `{"a":1,"\u0061":2}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := DecodeJSON([]byte(in))
			wantErr(t, err, ErrMalformed)
		})
	}
}

// RFC 7519 §4: claim names are unique, compared after unescaping as
// DecodeJSON compares them, so the member read is the one DecodeJSON reads.
func TestDecodeJSONStringMemberRejectsDuplicates(t *testing.T) {
	for name, in := range map[string]string{
		"same spelling":    `{"iss":"a","x":1,"iss":"b"}`,
		"escaped spelling": `{"iss":"a","\u0069ss":"b"}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := DecodeJSONStringMember([]byte(in), "iss")
			wantErr(t, err, ErrMalformed)
		})
	}
}

// The member read before the signature is the one DecodeJSON reads after
// it: only a top-level key counts, never one inside a string or a nested
// value, and what is not JSON is refused rather than walked.
func TestDecodeJSONStringMemberReadsTopLevelJSONOnly(t *testing.T) {
	for _, in := range []string{
		`{"a":"\"},\"iss\":\"b","iss":"a"}`,
		`{"a":{"iss":"b"},"iss":"a"}`,
		`{"a":["]}",{"iss":"b"}],"iss":"a"}`,
		` { "i\u0073s" : "a" } `,
	} {
		got, found, err := DecodeJSONStringMember([]byte(in), "iss")
		if err != nil || !found || got != "a" {
			t.Errorf("%s: got %q, %v, %v; want \"a\"", in, got, found, err)
		}
	}
	for _, in := range []string{`{"iss":"a"`, `{"iss":"a",}`, `{"iss":"a"} x`, `["iss","a"]`} {
		_, _, err := DecodeJSONStringMember([]byte(in), "iss")
		wantErr(t, err, ErrMalformed)
	}
}

// Only the member asked for is built, and only when it is a string. A 1 MiB
// payload holds a million small values, or a hundred thousand members, and
// building either costs millions of allocations before any signature is
// checked; the walk makes a few.
func TestDecodeJSONStringMemberBuildsNothingElse(t *testing.T) {
	for _, tc := range []struct {
		name, data string
		err        error
	}{
		{"iss an array of 2^19 zeros", `{"iss":[` + strings.Repeat("0,", 1<<19) + `0]}`, ErrMalformed},
		{"2^17 other members", `{"iss":"x"` + strings.Repeat(`,"":0`, 1<<17) + `}`, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := []byte(tc.data)
			var (
				iss string
				err error
			)
			allocs := testing.AllocsPerRun(1, func() { iss, _, err = DecodeJSONStringMember(data, "iss") })
			if tc.err != nil {
				wantErr(t, err, tc.err)
			} else if err != nil || iss != "x" {
				t.Fatalf("got %q, %v; want \"x\"", iss, err)
			}
			if allocs > 1000 {
				t.Fatalf("%v allocations", allocs)
			}
		})
	}
}

func TestDecodeJSONRejectsTrailingData(t *testing.T) {
	for _, in := range []string{`{"a":1}xyz`, `{"a":1}{"b":2}`, `{"a":1} 1`} {
		_, err := DecodeJSON([]byte(in))
		wantErr(t, err, ErrMalformed)
	}
	if _, err := DecodeJSON([]byte("{\"a\":1} \n")); err != nil {
		t.Fatalf("trailing whitespace must pass: %v", err)
	}
}

func TestDecodeJSONKeepsNumbers(t *testing.T) {
	v, err := DecodeJSONObject([]byte(`{"n":12345678901234567890123}`))
	if err != nil {
		t.Fatal(err)
	}
	n, ok := v["n"].(json.Number)
	if !ok || n.String() != "12345678901234567890123" {
		t.Fatalf("got %#v, want json.Number keeping every digit", v["n"])
	}
}

func TestDecodeJSONRejectsInvalidUTF8(t *testing.T) {
	_, err := DecodeJSON([]byte("{\"a\":\"\xff\"}"))
	wantErr(t, err, ErrMalformed)
}

func TestDecodeJSONObjectRejectsNonObject(t *testing.T) {
	for _, in := range []string{`[1]`, `"x"`, `1`, ``} {
		_, err := DecodeJSONObject([]byte(in))
		wantErr(t, err, ErrMalformed)
	}
}

func TestDecodeJSONEmptyArrayIsNotNil(t *testing.T) {
	v, err := DecodeJSONObject([]byte(`{"a":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if arr, ok := v["a"].([]any); !ok || arr == nil {
		t.Fatalf("got %#v, want a non-nil []any", v["a"])
	}
}

func TestEncodeJSONNoHTMLEscapingNoNewline(t *testing.T) {
	got, err := EncodeJSON(map[string]any{"b": "<a&b>", "a": "Nguyễn"})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"a":"Nguyễn","b":"<a&b>"}`; string(got) != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestDecodeJSONCapsNesting(t *testing.T) {
	nested := func(n int, open, close string) string {
		return strings.Repeat(open, n) + "1" + strings.Repeat(close, n)
	}
	for name, in := range map[string]string{
		"arrays at the limit":  nested(MaxJSONDepth, "[", "]"),
		"objects at the limit": nested(MaxJSONDepth, `{"a":`, "}"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeJSON([]byte(in)); err != nil {
				t.Fatalf("depth %d refused: %v", MaxJSONDepth, err)
			}
		})
	}
	for name, in := range map[string]string{
		"arrays one past the limit":  nested(MaxJSONDepth+1, "[", "]"),
		"objects one past the limit": nested(MaxJSONDepth+1, `{"a":`, "}"),
		"a megabyte of open arrays":  strings.Repeat("[", 1<<20),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := DecodeJSON([]byte(in))
			if !errors.Is(err, ErrMalformed) || !strings.Contains(err.Error(), "nesting deeper") {
				t.Fatalf("got %v, want the nesting limit as ErrMalformed", err)
			}
		})
	}
}

func TestEncodeJSONRejectsUnencodable(t *testing.T) {
	_, err := EncodeJSON(map[string]any{"f": func() {}})
	if !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("got %v, want ErrInvalidArgument", err)
	}
}
