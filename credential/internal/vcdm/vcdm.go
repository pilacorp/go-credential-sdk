// Package vcdm holds the small Verifiable Credentials Data Model helpers that
// both the vc and vp packages need.
//
// It lives under internal/ on purpose. These are not API: nothing outside this
// module should depend on them, and anything exported from credential/vc or
// credential/vp has to be kept working forever once a version is tagged. The
// alternative — a copy in each package — is how two checks that must agree drift
// apart, which is a bug this repository has already shipped once.
package vcdm

import (
	"fmt"
	"time"
)

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

// CheckValidityPeriod enforces a document's validFrom/validUntil (RFC 3339
// strings, empty when absent) at the current time, widened by leeway on both
// sides. what names the document in the error ("credential", "presentation").
func CheckValidityPeriod(what, validFrom, validUntil string, leeway time.Duration) error {
	now := time.Now()
	if validFrom != "" {
		t, err := time.Parse(time.RFC3339, validFrom)
		if err != nil {
			return fmt.Errorf("failed to parse validFrom: %w", err)
		}
		if now.Add(leeway).Before(t) {
			return fmt.Errorf("%s is not valid yet", what)
		}
	}

	if validUntil != "" {
		t, err := time.Parse(time.RFC3339, validUntil)
		if err != nil {
			return fmt.Errorf("failed to parse validUntil: %w", err)
		}
		if now.Add(-leeway).After(t) {
			return fmt.Errorf("%s is expired", what)
		}
	}

	return nil
}
