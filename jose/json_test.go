package jose

import (
	"encoding/json"
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
