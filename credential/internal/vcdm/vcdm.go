// Package vcdm holds the small Verifiable Credentials Data Model helpers that
// both the vc and vp packages need.
//
// It lives under internal/ on purpose. These are not API: nothing outside this
// module should depend on them, and anything exported from credential/vc or
// credential/vp has to be kept working forever once a version is tagged. The
// alternative — a copy in each package — is how two checks that must agree drift
// apart, which is a bug this repository has already shipped once.
package vcdm

// ContextV2 is the @context VC Data Model 2.0 § 4.2 requires first on every
// credential and presentation.
const ContextV2 = "https://www.w3.org/ns/credentials/v2"

// ContextV1 is the VC 1.1 base context. Recognised, never written.
const ContextV1 = "https://www.w3.org/2018/credentials/v1"

// HasType reports whether a type property names want. The data model defines the
// property as an array, but a single type is commonly written as a bare string,
// so both shapes are read.
func HasType(v interface{}, want string) bool {
	switch t := v.(type) {
	case string:
		return t == want
	case []interface{}:
		for _, e := range t {
			if s, ok := e.(string); ok && s == want {
				return true
			}
		}
	case []string:
		for _, s := range t {
			if s == want {
				return true
			}
		}
	}

	return false
}

// FirstContext returns the first entry of an @context property, which is the one
// the data model pins. A bare string counts as its own first entry; anything
// else yields "" and the caller reports it.
func FirstContext(v interface{}) string {
	switch c := v.(type) {
	case string:
		return c
	case []interface{}:
		if len(c) > 0 {
			first, _ := c[0].(string)

			return first
		}
	case []string:
		if len(c) > 0 {
			return c[0]
		}
	}

	return ""
}
