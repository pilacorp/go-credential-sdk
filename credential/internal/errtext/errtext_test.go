package errtext

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestClip(t *testing.T) {
	if got := Clip("did:example:issuer"); got != "did:example:issuer" {
		t.Errorf("Clip(short) = %q, want it unchanged", got)
	}
	got := Clip(strings.Repeat("x", 300))
	if len(got) != 259 || !strings.HasSuffix(got, "...") {
		t.Errorf("Clip(300 bytes) has %d bytes, want 256 and \"...\"", len(got))
	}
}

func TestClip_KeepsUTF8Whole(t *testing.T) {
	got := Clip("a" + strings.Repeat("é", 200)) // 'é' is 2 bytes; byte 256 falls inside one
	if !utf8.ValidString(got) {
		t.Errorf("Clip cut a UTF-8 character: %q", got)
	}
}
