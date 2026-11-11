package jose

import (
	"bytes"
	"testing"
)

func TestDecodeSegmentRoundTrip(t *testing.T) {
	for _, b := range [][]byte{{}, {0}, {0xff, 0xfe}, []byte("héllo <&>")} {
		got, err := DecodeSegment(EncodeSegment(b))
		if err != nil || !bytes.Equal(got, b) {
			t.Fatalf("round trip of %x: got %x, %v", b, got, err)
		}
	}
}

// "QQ" is the canonical encoding of "A"; "QR" differs only in trailing bits a
// lenient decoder drops, giving a second spelling of the same bytes.
func TestDecodeSegmentRejectsNonZeroTrailingBits(t *testing.T) {
	if _, err := DecodeSegment("QQ"); err != nil {
		t.Fatalf("canonical QQ: %v", err)
	}
	_, err := DecodeSegment("QR")
	wantErr(t, err, ErrMalformed)
}

// Go's decoder skips \r and \n even in strict mode.
func TestDecodeSegmentRejectsLineBreaks(t *testing.T) {
	for _, s := range []string{"QQ\n", "Q\nQ", "QQ\r", "\r\nQQ"} {
		_, err := DecodeSegment(s)
		wantErr(t, err, ErrMalformed)
	}
}

func TestDecodeSegmentRejectsPaddingAndStdAlphabet(t *testing.T) {
	for _, s := range []string{"QQ==", "+/8", "ab/c"} {
		_, err := DecodeSegment(s)
		wantErr(t, err, ErrMalformed)
	}
}
