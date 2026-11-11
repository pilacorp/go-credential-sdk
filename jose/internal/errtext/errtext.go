// Package errtext writes values taken from a received token into error texts.
// No standard covers it: a name or alg can be up to the size of the token, and
// an error text is logged and passed on, so it carries a bounded prefix only.
package errtext

import (
	"strconv"
	"unicode/utf8"
)

// maxBytes is the most of a value Quote keeps. The quoted form of 32 bytes is
// at most 133 bytes ("\x00" is four bytes for one), whatever the value holds.
const maxBytes = 32

// Quote returns s quoted as by strconv.Quote, cut to its first 32 bytes at a
// rune boundary and followed by "..." when cut. The limit counts bytes, not
// runes: %.32q keeps 32 runes, up to 322 bytes once quoted.
func Quote(s string) string {
	if len(s) <= maxBytes {
		return strconv.Quote(s)
	}
	cut := maxBytes
	for i := 1; i < utf8.UTFMax && !utf8.RuneStart(s[cut]); i++ {
		cut--
	}
	return strconv.Quote(s[:cut]) + "..."
}
