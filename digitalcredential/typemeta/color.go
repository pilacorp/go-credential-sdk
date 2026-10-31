// Colors of the simple rendering method (draft-ietf-oauth-sd-jwt-vc-19
// §5.5.1.1): an RGB color value of CSS Color Level 3 §4.2.1, numbers as CSS
// 2.1 §4.3.1 writes them, case-insensitive (CSS 2.1 §4.1.3).

package typemeta

import "strings"

// rgbColor reports whether s is "#" with 3 or 6 hex digits, or "rgb(" with
// three integers or three percentages separated by commas, whitespace
// allowed around each, and ")". A keyword such as "white" is a color
// keyword (§4.3), not an RGB value.
func rgbColor(s string) bool {
	if h, ok := strings.CutPrefix(s, "#"); ok {
		return (len(h) == 3 || len(h) == 6) && strings.Trim(strings.ToLower(h), "0123456789abcdef") == ""
	}
	if len(s) < len("rgb()") || !strings.EqualFold(s[:4], "rgb(") || s[len(s)-1] != ')' {
		return false
	}
	vals := strings.Split(s[4:len(s)-1], ",")
	if len(vals) != 3 {
		return false
	}
	pct := strings.HasSuffix(strings.Trim(vals[0], cssSpace), "%")
	for _, v := range vals {
		v = strings.Trim(v, cssSpace)
		if n, ok := strings.CutSuffix(v, "%"); ok != pct || (pct && !cssNumber(n)) || (!pct && !cssInteger(n)) {
			return false
		}
	}
	return true
}

// cssSpace is the whitespace of CSS 2.1 §4.1.1 (s: space, tab, LF, CR, FF).
const cssSpace = " \t\n\r\f"

// cssInteger is CSS 2.1 §4.3.1 <integer>: [+-]?[0-9]+.
func cssInteger(s string) bool {
	if s != "" && (s[0] == '+' || s[0] == '-') {
		s = s[1:]
	}
	return s != "" && digit(s)
}

// cssNumber is CSS 2.1 §4.3.1 <number>: [+-]?([0-9]+ | [0-9]*\.[0-9]+).
func cssNumber(s string) bool {
	if s != "" && (s[0] == '+' || s[0] == '-') {
		s = s[1:]
	}
	intPart, frac, dot := strings.Cut(s, ".")
	if !dot {
		return intPart != "" && digit(intPart)
	}
	return digit(intPart) && frac != "" && digit(frac)
}
