package vc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"
)

// decodeExactMembers decodes data, one JSON value, into v, a pointer to a
// struct, matching member names case-sensitively as VC Render Method defines
// them. encoding/json matches names case-insensitively, so it would read
// "TEMPLATE" as template, which every other processor ignores. A member that
// differs from a field name only in case is dropped, as an unknown member is
// ignored; with strict, it is refused, and so is any other unknown member.
//
// The walk sees only fields with a named json tag; a type with its own
// UnmarshalJSON applies its own member rules.
func decodeExactMembers(data []byte, v any, strict bool) error {
	var tree any
	if err := decodeOneValue(data, &tree, false); err != nil {
		return err
	}
	dropped, err := dropCaseVariants(tree, reflect.TypeOf(v), strict)
	if err != nil {
		return err
	}
	if dropped {
		// Encode what is left; without a drop the input already is that text.
		if data, err = json.Marshal(tree); err != nil {
			return err
		}
	}
	return decodeOneValue(data, v, strict)
}

// decodeOneValue decodes data into v and refuses anything after the first
// value, as json.Unmarshal does (RFC 8259 §2). Numbers stay exact in a tree.
func decodeOneValue(data []byte, v any, strict bool) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if strict {
		decoder.DisallowUnknownFields()
	}
	if err := decoder.Decode(v); err != nil {
		return err
	}
	// More() does not see a stray "}" or "]", so read one more token.
	if _, err := decoder.Token(); err != io.EOF {
		return fmt.Errorf("unexpected data after the JSON value")
	}
	return nil
}

var jsonUnmarshalerType = reflect.TypeOf((*json.Unmarshaler)(nil)).Elem()

// dropCaseVariants walks node along the Go type it decodes into and reports
// whether it dropped a member.
func dropCaseVariants(node any, t reflect.Type, strict bool) (bool, error) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if reflect.PointerTo(t).Implements(jsonUnmarshalerType) {
		return false, nil
	}
	dropped := false
	switch t.Kind() {
	case reflect.Struct:
		object, ok := node.(map[string]any)
		if !ok {
			return false, nil
		}
		fields := jsonFieldTypes(t)
		for key, value := range object {
			if fieldType, ok := fields[key]; ok {
				inner, err := dropCaseVariants(value, fieldType, strict)
				if err != nil {
					return false, err
				}
				dropped = dropped || inner
				continue
			}
			for name := range fields {
				if !strings.EqualFold(key, name) {
					continue
				}
				if strict {
					// The member name comes from the credential, so only its start is quoted.
					return false, fmt.Errorf("unknown member %.64q; member names are case-sensitive", key)
				}
				delete(object, key)
				dropped = true
				break
			}
		}
	case reflect.Slice, reflect.Array:
		items, _ := node.([]any)
		for _, item := range items {
			inner, err := dropCaseVariants(item, t.Elem(), strict)
			if err != nil {
				return false, err
			}
			dropped = dropped || inner
		}
	}
	return dropped, nil
}

// jsonFieldTypes maps the JSON member names of a struct's tagged fields to
// their types.
func jsonFieldTypes(t reflect.Type) map[string]reflect.Type {
	fields := make(map[string]reflect.Type, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		if name, _, _ := strings.Cut(field.Tag.Get("json"), ","); name != "" && name != "-" {
			fields[name] = field.Type
		}
	}
	return fields
}
