package sdjwt

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/pilacorp/go-credential-sdk/jose"
)

// Split refuses oversized input before it allocates the parts; an SD-JWT of
// exactly 1 MiB is accepted.
func TestSplitLimits(t *testing.T) {
	const jwt = "eyJh.eyJw.c2ln"
	// sized is an SD-JWT of n bytes: the JWT and one disclosure, no KB-JWT.
	sized := func(n int) string { return jwt + "~" + strings.Repeat("A", n-len(jwt)-2) + "~" }
	if _, _, _, err := Split(sized(1 << 20)); err != nil {
		t.Fatalf("1 MiB: got %v, want nil", err)
	}
	var distinct strings.Builder // 1001 different disclosures
	for i := range 1001 {
		fmt.Fprintf(&distinct, "~d%d", i)
	}
	for _, tc := range []struct {
		name    string
		compact string
	}{
		{"1 MiB + 1 byte", sized(1<<20 + 1)},
		{"1001 disclosures", jwt + distinct.String() + "~"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, _, err := Split(tc.compact); !errors.Is(err, jose.ErrMalformed) {
				t.Fatalf("got %v, want jose.ErrMalformed", err)
			}
		})
	}
}
