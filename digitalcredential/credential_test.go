package dc

import (
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/pilacorp/go-credential-sdk/jose"
)

// RFC 7515 Appendix A.3, and the same token with its signature's S replaced
// by n−S of P-256, which verifies too. Each hash is SHA-256 of the JWT's
// ASCII bytes, computed with shasum, not by this package.
const (
	rfc7515A3 = "eyJhbGciOiJFUzI1NiJ9." +
		"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
		"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ." +
		"DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSA" +
		"pmWQxfKTUJqPP3-Kg6NU1Q"
	rfc7515A3Twin = "eyJhbGciOiJFUzI1NiJ9." +
		"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
		"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ." +
		"DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmU69fgrc8OPGycO0lD3tat_" +
		"FoFp57SETepkeks4eL_QfA"
)

// TC-30 (REQ-48, REQ-49, REQ-51): Serialize gives the string back exactly,
// and Hash covers only the Issuer-signed JWT as received, so a presentation
// keeps the hash and the S-flipped twin is another credential.
func TestHashRFC7515AppendixA3(t *testing.T) {
	const (
		hashA3   = "4634b4dcaca24964bce48e22146fb6e3933ad993e6f24f42575145a2133ae115"
		hashTwin = "d16175719f45a5fc088c1d95733040976389315a3f4739fea801a516234c51d1"
	)
	for _, tc := range []struct{ name, compact, want string }{
		{"SD-JWT", rfc7515A3 + "~", hashA3},
		{"with a disclosure", rfc7515A3 + "~WyJhIl0~", hashA3},
		{"with a disclosure and a KB-JWT", rfc7515A3 + "~WyJhIl0~" + rfc7515A3Twin, hashA3},
		{"S changed to n−S", rfc7515A3Twin + "~", hashTwin},
	} {
		c, err := Parse(tc.compact)
		if err != nil {
			t.Fatalf("%s: Parse: %v", tc.name, err)
		}
		if got := c.Serialize(); got != tc.compact {
			t.Errorf("%s: Serialize = %q, want the input", tc.name, got)
		}
		if got, err := c.Hash(); err != nil || got != tc.want {
			t.Errorf("%s: Hash = %s, %v; want %s", tc.name, got, err, tc.want)
		}
	}
}

// TC-34 (REQ-49): what sdjwt.Split refuses is *Error with CodeMalformed that
// also matches jose.ErrMalformed.
func TestParseRefusesMalformed(t *testing.T) {
	for name, compact := range map[string]string{
		"empty":                 "",
		"bare JWT without ~":    rfc7515A3,
		"over 1 MiB":            rfc7515A3 + "~" + strings.Repeat("A", 1<<20) + "~",
		"over 1000 disclosures": rfc7515A3 + "~" + manyDisclosures(1001),
	} {
		_, err := Parse(compact)
		var e *Error
		if !errors.As(err, &e) || e.Code != CodeMalformed || !errors.Is(err, jose.ErrMalformed) {
			t.Errorf("%s: Parse err = %v; want *Error MALFORMED wrapping jose.ErrMalformed", name, err)
		}
	}
}

// manyDisclosures returns n distinct disclosure strings, each followed by ~.
func manyDisclosures(n int) string {
	var b strings.Builder
	for i := range n {
		b.WriteString(jose.EncodeSegment([]byte(`["salt",` + strconv.Itoa(i) + `]`)))
		b.WriteByte('~')
	}
	return b.String()
}

// TC-35 (REQ-25, REQ-48, REQ-51): a nil or zero Credential is not a
// credential: no hash of "", no presentation, and no panic.
func TestZeroCredential(t *testing.T) {
	for name, c := range map[string]*Credential{"nil": nil, "zero": {}} {
		if got := c.Serialize(); got != "" {
			t.Errorf("%s: Serialize = %q, want empty", name, got)
		}
		if _, err := c.Hash(); !errors.Is(err, jose.ErrInvalidArgument) {
			t.Errorf("%s: Hash err = %v; want jose.ErrInvalidArgument", name, err)
		}
		if _, err := c.Present(t.Context(), PresentRequest{}); !errors.Is(err, jose.ErrInvalidArgument) {
			t.Errorf("%s: Present err = %v; want jose.ErrInvalidArgument", name, err)
		}
	}
}
