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

// A member of another type is refused without being built: a megabyte of
// [0,0,...] decodes into millions of values, and a scan makes a few dozen.
func TestDecodeJSONStringMemberRefusesOtherTypesUnread(t *testing.T) {
	data := []byte(`{"iss":[` + strings.Repeat("0,", 1<<19) + `0]}`)
	var err error
	allocs := testing.AllocsPerRun(1, func() { _, _, err = DecodeJSONStringMember(data, "iss") })
	wantErr(t, err, ErrMalformed)
	if allocs > 1000 {
		t.Fatalf("%v allocations for a non-string member", allocs)
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
