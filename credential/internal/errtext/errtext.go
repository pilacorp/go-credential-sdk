// Package errtext bounds the input values copied into error messages. A value
// from a fetched or presented document can be megabytes long, and callers log
// the errors the SDK returns.
package errtext

import "unicode/utf8"

// maxValue is the most bytes of one value an error message carries.
const maxValue = 256

// Clip returns s cut to at most its first 256 bytes, with "..." when it was
// cut. The cut falls on a UTF-8 character boundary, so a valid string stays
// valid in logs.
func Clip(s string) string {
	if len(s) <= maxValue {
		return s
	}
	n := maxValue
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "..."
}
