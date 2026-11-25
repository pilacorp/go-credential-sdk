package jsoncanonicalizer

import (
	"strings"
	"testing"
)

// TestNestingDepthBounded checks that deep nesting is refused with an error
// instead of overflowing the stack, which would end the process.
func TestNestingDepthBounded(t *testing.T) {
	nested := func(open, close string, n int) string {
		return strings.Repeat(open, n) + strings.Repeat(close, n)
	}
	for _, tt := range []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"arrays at the limit", nested("[", "]", maxNestingDepth), false},
		{"arrays over the limit", nested("[", "]", maxNestingDepth+1), true},
		{"objects over the limit", "{" + nested(`"a":{`, "}", maxNestingDepth) + "}", true},
		{"two million levels", nested("[", "]", 2_000_000), true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Transform([]byte(tt.input))
			if (err != nil) != tt.wantErr {
				t.Errorf("Transform error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
