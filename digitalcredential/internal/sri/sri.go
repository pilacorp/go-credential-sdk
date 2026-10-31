// Package sri reads an "integrity metadata" string, the value of vct#integrity,
// extends#integrity and uri#integrity in draft-ietf-oauth-sd-jwt-vc-19 §6,
// with the syntax of W3C Subresource Integrity (REC 2016-06-23) §3.5 and the
// parsing of §3.3.3, and checks a document against it as §6 says. typemeta
// checks documents with it; dc checks at issuance that vct#integrity is well
// formed.
package sri

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"strings"
)

// algs are the hash algorithms of CSP Level 2 §4.2 hash-algo, strongest
// first, as draft 19 §6 asks the strongest one supported to be used.
var algs = []struct {
	name string
	sum  func([]byte) []byte
}{
	{"sha512", func(b []byte) []byte { s := sha512.Sum512(b); return s[:] }},
	{"sha384", func(b []byte) []byte { s := sha512.Sum384(b); return s[:] }},
	{"sha256", func(b []byte) []byte { s := sha256.Sum256(b); return s[:] }},
}

// WellFormed reports whether integrity is "integrity metadata" as SRI §3.5
// writes it and draft 19 §5.3 requires of vct#integrity: at least one token,
// and every token hash-algo "-" base64-value with options of VCHAR only.
func WellFormed(integrity string) bool {
	n := 0
	for tok := range strings.FieldsFuncSeq(integrity, isASCIISpace) {
		if _, _, ok := parseToken(tok); !ok {
			return false
		}
		n++
	}
	return n > 0
}

// Check reports whether data matches integrity: draft 19 §6, the digest of
// exactly data under the strongest algorithm integrity uses, compared octet
// for octet with each digest of that algorithm. The error names which of the
// two §6 failures it is and quotes nothing of integrity.
func Check(data []byte, integrity string) error {
	alg, digests := strongest(integrity)
	if alg < 0 {
		return errors.New("integrity metadata holds no sha256, sha384 or sha512 hash expression")
	}
	sum := algs[alg].sum(data)
	for _, d := range digests {
		if bytes.Equal(sum, d) {
			return nil
		}
	}
	return errors.New("the document does not match its " + algs[alg].name + " integrity metadata")
}

// strongest parses integrity as SRI §3.3.3 does: split on ASCII whitespace,
// skip a token that is not valid metadata (parseToken). It returns the index
// in algs of the strongest algorithm left, -1 for none, and the decoded
// digests that algorithm carries.
func strongest(integrity string) (alg int, digests [][]byte) {
	alg = -1
	for tok := range strings.FieldsFuncSeq(integrity, isASCIISpace) {
		i, value, ok := parseToken(tok)
		if !ok || (alg >= 0 && i > alg) {
			continue
		}
		// base64-value allows any padding up to "==", so it is decoded
		// unpadded. A value that does not decode, or decodes to the wrong
		// length, is still a valid token of its algorithm (§3.3.3), and
		// matches no document.
		d, _ := base64.RawStdEncoding.DecodeString(strings.TrimRight(value, "="))
		if i < alg || alg < 0 {
			alg, digests = i, nil
		}
		digests = append(digests, d)
	}
	return alg, digests
}

// parseToken reads one token as SRI §3.5 hash-with-options: hash-algo "-"
// base64-value, then options "?" *VCHAR. It returns the index in algs of its
// algorithm and its base64-value, and false when the token is not valid
// metadata. hash-algo is matched in ASCII case only (ABNF, RFC 5234 §2.3):
// the length check keeps strings.EqualFold from folding a multi-byte letter,
// such as U+017F, onto an ASCII one.
func parseToken(tok string) (alg int, value string, ok bool) {
	tok, opts, _ := strings.Cut(tok, "?")
	for i := 0; i < len(opts); i++ {
		if opts[i] < 0x21 || opts[i] > 0x7e {
			return -1, "", false
		}
	}
	name, value, ok := strings.Cut(tok, "-")
	if !ok || !base64Value(value) {
		return -1, "", false
	}
	for j, a := range algs {
		if len(name) == len(a.name) && strings.EqualFold(name, a.name) {
			return j, value, true
		}
	}
	return -1, "", false
}

// base64Value is CSP Level 2 §4.2: 1*( ALPHA / DIGIT / "+" / "/" ) *2( "=" ).
func base64Value(s string) bool {
	body := strings.TrimRight(s, "=")
	if body == "" || len(s)-len(body) > 2 {
		return false
	}
	for i := 0; i < len(body); i++ {
		c := body[i]
		if !('A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '+' || c == '/') {
			return false
		}
	}
	return true
}

// isASCIISpace: SRI splits on ASCII whitespace, never on other Unicode
// spaces.
func isASCIISpace(r rune) bool {
	return r == ' ' || r == '\t' || r == '\n' || r == '\f' || r == '\r'
}
