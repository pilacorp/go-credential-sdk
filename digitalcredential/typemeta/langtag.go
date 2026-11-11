// Language tags of display metadata (draft-ietf-oauth-sd-jwt-vc-19 §5.5,
// §5.6.2): well-formed per the ABNF of RFC 5646 §2.1, case-insensitive
// (§2.1.1).

package typemeta

import "strings"

// irregular are the grandfathered tags of RFC 5646 §2.1 that langtag does
// not match; the regular ones (art-lojban, zh-min-nan, …) match it.
var irregular = map[string]bool{
	"en-gb-oed": true, "i-ami": true, "i-bnn": true, "i-default": true,
	"i-enochian": true, "i-hak": true, "i-klingon": true, "i-lux": true,
	"i-mingo": true, "i-navajo": true, "i-pwn": true, "i-tao": true,
	"i-tay": true, "i-tsu": true, "sgn-be-fr": true, "sgn-be-nl": true,
	"sgn-ch-de": true,
}

// wellFormedLangTag reports whether s is a well-formed language tag (RFC
// 5646 §2.2.9): langtag, privateuse or grandfathered. Whether its subtags are
// registered ("valid", §2.2.9) needs the IANA registry and is not checked.
func wellFormedLangTag(s string) bool {
	// ASCII only before folding: strings.ToLower maps some non-ASCII runes,
	// such as U+212A KELVIN SIGN, to ASCII letters.
	if strings.Trim(s, "-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") != "" {
		return false
	}
	s = strings.ToLower(s)
	if irregular[s] {
		return true
	}
	subs := strings.Split(s, "-")
	for _, t := range subs {
		if t == "" || len(t) > 8 || strings.Trim(t, "abcdefghijklmnopqrstuvwxyz0123456789") != "" {
			return false
		}
	}
	i := 0
	next := func(ok func(string) bool) bool {
		if i < len(subs) && ok(subs[i]) {
			i++
			return true
		}
		return false
	}
	if subs[0] != "x" {
		// language = 2*3ALPHA ["-" extlang] / 4ALPHA / 5*8ALPHA
		if !next(func(t string) bool { return len(t) >= 2 && alpha(t) }) {
			return false
		}
		if len(subs[0]) <= 3 {
			// extlang = 3ALPHA *2("-" 3ALPHA)
			for n := 0; n < 3 && next(func(t string) bool { return len(t) == 3 && alpha(t) }); n++ {
			}
		}
		next(func(t string) bool { return len(t) == 4 && alpha(t) })                            // script
		next(func(t string) bool { return len(t) == 2 && alpha(t) || len(t) == 3 && digit(t) }) // region
		for next(func(t string) bool { return len(t) >= 5 || len(t) == 4 && digit(t[:1]) }) {   // variant
		}
		// extension = singleton 1*("-" (2*8alphanum)); "x" starts privateuse.
		for i < len(subs) && len(subs[i]) == 1 && subs[i] != "x" {
			i++
			if !next(func(t string) bool { return len(t) >= 2 }) {
				return false
			}
			for next(func(t string) bool { return len(t) >= 2 }) {
			}
		}
	}
	// privateuse = "x" 1*("-" (1*8alphanum))
	if next(func(t string) bool { return t == "x" }) {
		if i == len(subs) {
			return false
		}
		i = len(subs)
	}
	return i == len(subs)
}

func alpha(s string) bool { return strings.Trim(s, "abcdefghijklmnopqrstuvwxyz") == "" }
func digit(s string) bool { return strings.Trim(s, "0123456789") == "" }
