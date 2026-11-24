package didjwtvc

import (
	"math"
	"strconv"
	"time"
)

// The helpers below give decoded JSON values the JavaScript semantics
// converters.ts relies on: truthiness, object spread, asArray, Set
// de-duplication and Date.toISOString.

// jsISODate is new Date(seconds * 1000).toISOString().
func jsISODate(v interface{}) (string, error) {
	seconds, ok := v.(float64)
	if !ok {
		return "", ErrUnsupported // not ported: JavaScript number coercion
	}
	ms := math.Trunc(seconds * 1000)
	if math.IsNaN(ms) || math.Abs(ms) > 8.64e15 {
		return "", ErrUnsupported // JavaScript Date throws RangeError
	}
	t := time.UnixMilli(int64(ms)).UTC()
	if t.Year() < 0 || t.Year() > 9999 {
		return "", ErrUnsupported // toISOString's six-digit years, not ported
	}
	return t.Format("2006-01-02T15:04:05.000Z"), nil
}

// jsTruthy is JavaScript truthiness for a decoded JSON value.
func jsTruthy(v interface{}) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case float64:
		return t != 0 && !math.IsNaN(t)
	case string:
		return t != ""
	default:
		return true
	}
}

// jsTypeofObject is typeof v === "object": objects, arrays and null.
func jsTypeofObject(v interface{}) bool {
	switch v.(type) {
	case nil, map[string]interface{}, []interface{}:
		return true
	}
	return false
}

// jsMember is v?.[key] for a decoded JSON value: only objects have members
// that JSON can carry.
func jsMember(v interface{}, key string) interface{} {
	if m, ok := v.(map[string]interface{}); ok {
		return m[key]
	}
	return nil
}

// jsSpread copies the own enumerable properties of v into dst, as {...v}.
func jsSpread(dst map[string]interface{}, v interface{}) {
	switch t := v.(type) {
	case map[string]interface{}:
		for k, val := range t {
			dst[k] = val
		}
	case []interface{}:
		for i, val := range t {
			dst[strconv.Itoa(i)] = val
		}
	case string:
		for i, r := range []rune(t) {
			dst[strconv.Itoa(i)] = string(r)
		}
	}
}

// jsKeyCount is Object.keys(v).length for a truthy decoded JSON value.
func jsKeyCount(v interface{}) int {
	switch t := v.(type) {
	case map[string]interface{}:
		return len(t)
	case []interface{}:
		return len(t)
	case string:
		return len([]rune(t))
	}
	return 0
}

// jsAsArray is asArray in did-jwt-vc: an array as-is, anything else wrapped.
// A missing member is undefined, which notEmpty later drops like null.
func jsAsArray(v interface{}) []interface{} {
	if a, ok := v.([]interface{}); ok {
		return a
	}
	return []interface{}{v}
}

// jsDedup is [...new Set(lists.flat().filter(notEmpty))]: primitives are
// de-duplicated by value, objects and arrays are never equal to each other.
func jsDedup(lists ...[]interface{}) []interface{} {
	out := []interface{}{}
	seen := map[interface{}]bool{}
	for _, list := range lists {
		for _, v := range list {
			switch v.(type) {
			case nil:
				continue
			case string, float64, bool:
				if seen[v] {
					continue
				}
				seen[v] = true
			}
			out = append(out, v)
		}
	}
	return out
}
