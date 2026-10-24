package sdjwt

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/pilacorp/go-credential-sdk/jose"
)

// Split refuses oversized input before it allocates the parts.
func TestSplitLimits(t *testing.T) {
	const jwt = "eyJh.eyJw.c2ln"
	var distinct strings.Builder // 1001 different disclosures
	for i := range 1001 {
		fmt.Fprintf(&distinct, "~d%d", i)
	}
	for _, tc := range []struct {
		name    string
		compact string
	}{
		{"over 1 MB", jwt + "~" + strings.Repeat("A", 1<<20) + "~"},
		{"1001 disclosures", jwt + distinct.String() + "~"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, _, err := Split(tc.compact); !errors.Is(err, jose.ErrMalformed) {
				t.Fatalf("got %v, want jose.ErrMalformed", err)
			}
		})
	}
}
