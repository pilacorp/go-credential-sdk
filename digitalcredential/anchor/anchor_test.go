package anchor

import (
	"encoding/hex"
	"testing"
)

// RFC 7515 Appendix A.3, and the same token with its signature's S replaced
// by n−S of P-256, which verifies too. Each leaf is SHA-256 of the token's
// ASCII bytes, computed with shasum, not by this package. The leaves differ:
// the leaf is these bytes, so the twin is another credential.
// The rows after the first wrap A.3 as RFC 9901 §4 writes an SD-JWT and an
// SD-JWT+KB, the twin as the KB-JWT, so cutting at any "~" but the first, or
// hashing the whole string, gives another leaf.
func TestLeafRFC7515AppendixA3(t *testing.T) {
	const (
		a3 = "eyJhbGciOiJFUzI1NiJ9." +
			"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
			"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ." +
			"DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSA" +
			"pmWQxfKTUJqPP3-Kg6NU1Q"
		twin = "eyJhbGciOiJFUzI1NiJ9." +
			"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
			"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ." +
			"DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmU69fgrc8OPGycO0lD3tat_" +
			"FoFp57SETepkeks4eL_QfA"
		leafA3   = "4634b4dcaca24964bce48e22146fb6e3933ad993e6f24f42575145a2133ae115"
		leafTwin = "d16175719f45a5fc088c1d95733040976389315a3f4739fea801a516234c51d1"
	)
	tests := []struct{ name, token, want string }{
		{"A.3", a3, leafA3},
		{"A.3 SD-JWT", a3 + "~", leafA3},
		{"A.3 SD-JWT with disclosures", a3 + "~WyJhIl0~WyJiIl0~", leafA3},
		{"A.3 SD-JWT+KB", a3 + "~WyJhIl0~" + twin, leafA3},
		{"twin", twin, leafTwin},
	}
	for _, tt := range tests {
		if got := Leaf(tt.token); hex.EncodeToString(got[:]) != tt.want {
			t.Errorf("%s: leaf %x, want %s", tt.name, got, tt.want)
		}
	}
}

// The on-chain ids of NDA DID's digital credential status lists; the second
// fails a format that writes the width as a constant.
func TestChainListID(t *testing.T) {
	if got := ChainListID(1, 7); got != "dc-b1-7" {
		t.Fatalf("ChainListID(1, 7) = %q, want dc-b1-7", got)
	}
	if got := ChainListID(2, 15); got != "dc-b2-15" {
		t.Fatalf("ChainListID(2, 15) = %q, want dc-b2-15", got)
	}
}
