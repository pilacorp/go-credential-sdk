package statuslist

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"

	"github.com/pilacorp/go-credential-sdk/jose"
)

// Encode returns the lst value of a token: the raw bytes compressed with ZLIB
// (RFC 1950: header and Adler-32 checksum, not raw DEFLATE) at the best
// compression level, then base64url without padding (draft 21 §4.1, §4.2).
func (l *List) Encode() (string, error) {
	var buf bytes.Buffer
	w, err := zlib.NewWriterLevel(&buf, zlib.BestCompression)
	if err != nil {
		return "", err
	}
	if _, err := w.Write(l.data); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	return jose.EncodeSegment(buf.Bytes()), nil
}

// Decode reads an lst with bits bits per entry, inflating at most
// DefaultMaxListBytes. See decode.
func Decode(lst string, bits int) (*List, error) {
	return decode(lst, bits, DefaultMaxListBytes)
}

// decode reads lst strictly:
//   - base64url without padding or line breaks, as jose.DecodeSegment;
//   - a ZLIB stream (a raw DEFLATE stream or a preset dictionary is refused),
//     whose Adler-32 checksum is verified and after which nothing follows;
//   - inflated through io.LimitReader(limit+1): more than limit bytes is
//     ErrTooLarge. A few KB of lst could otherwise inflate to gigabytes
//     (statium sets no limit).
func decode(lst string, bits int, limit int64) (*List, error) {
	if !validBits(bits) {
		return nil, fmt.Errorf("%w: bits %d, want 1, 2, 4 or 8", ErrMalformed, bits)
	}
	compressed, err := jose.DecodeSegment(lst)
	if err != nil {
		return nil, fmt.Errorf("%w: lst: %w", ErrMalformed, err)
	}
	src := bytes.NewReader(compressed)
	z, err := zlib.NewReader(src)
	if err != nil {
		return nil, fmt.Errorf("%w: lst is not a ZLIB stream: %v", ErrMalformed, err)
	}
	raw, err := io.ReadAll(io.LimitReader(z, limit+1))
	if int64(len(raw)) > limit {
		return nil, fmt.Errorf("%w: lst inflates past %d bytes", ErrTooLarge, limit)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: lst: %v", ErrMalformed, err)
	}
	if src.Len() != 0 {
		return nil, fmt.Errorf("%w: lst has %d bytes after the ZLIB stream", ErrMalformed, src.Len())
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("%w: lst inflates to an empty list", ErrMalformed)
	}
	return &List{bits: bits, size: len(raw) * 8 / bits, data: raw}, nil
}
