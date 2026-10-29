// The lst value: draft-ietf-oauth-status-list-21 §4.1 step 4 and §4.2, ZLIB
// (RFC 1950) around DEFLATE, then base64url without padding (draft 21 §3,
// RFC 7515 §2).

package statuslist

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"

	"github.com/pilacorp/go-credential-sdk/jose"
)

// Encode returns the lst of the list: its byte array compressed with DEFLATE
// at the best compression level in the ZLIB format (draft 21 §4.1 step 4),
// then base64url-encoded (§4.2).
func (l *List) Encode() (string, error) {
	if !l.valid() {
		return "", fmt.Errorf("%w: statuslist: list not made by New, FromBytes or Decode", jose.ErrInvalidArgument)
	}
	var buf bytes.Buffer
	w, err := zlib.NewWriterLevel(&buf, zlib.BestCompression)
	if err != nil {
		return "", fmt.Errorf("statuslist: zlib: %w", err)
	}
	if _, err := w.Write(l.b); err != nil {
		return "", fmt.Errorf("statuslist: zlib: %w", err)
	}
	if err := w.Close(); err != nil {
		return "", fmt.Errorf("statuslist: zlib: %w", err)
	}
	return jose.EncodeSegment(buf.Bytes()), nil
}

// Decode reads lst, the lst member of a Status List (draft 21 §4.2), as a
// list of bits-bit entries. It refuses, with jose.ErrMalformed:
//   - bits other than 1, 2, 4 or 8, and lst that is not strict base64url;
//   - a ZLIB stream with a bad header or Adler-32 checksum (RFC 1950 §2.3),
//     or with a preset dictionary: §2.3 requires rejecting one when the
//     enclosing format uses none, and draft 21 uses none;
//   - a byte array over 16 MiB.
//
// An empty byte array is a list with no entries: §4.1 step 2 sets no minimum
// size, and every index is then out of bounds, which §8.3 step 6 rejects.
// Data after the ZLIB stream is ignored, as RFC 1950 §2.2 leaves it outside
// the stream. Decode refuses a list over 16 MiB while inflating; CPU time and
// the memory for decoding lst grow with len(lst), so a caller reading lst from
// the network bounds its length first.
func Decode(lst string, bits int) (*List, error) {
	if !validBits(bits) {
		return nil, fmt.Errorf("%w: statuslist: bits %d, want 1, 2, 4 or 8", jose.ErrMalformed, bits)
	}
	raw, err := jose.DecodeSegment(lst)
	if err != nil {
		return nil, fmt.Errorf("statuslist: lst: %w", err)
	}
	// RFC 1950 §2.2: FDICT is bit 5 of FLG, the second byte. compress/zlib
	// accepts it when the dictionary id is that of an empty dictionary.
	if len(raw) >= 2 && raw[1]&0x20 != 0 {
		return nil, fmt.Errorf("%w: statuslist: lst uses a preset dictionary", jose.ErrMalformed)
	}
	zr, err := zlib.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("%w: statuslist: lst: %v", jose.ErrMalformed, err)
	}
	// Reading to EOF verifies the Adler-32 checksum; nothing else needs closing.
	b, err := io.ReadAll(io.LimitReader(zr, maxListBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: statuslist: lst: %v", jose.ErrMalformed, err)
	}
	if len(b) > maxListBytes {
		return nil, fmt.Errorf("%w: statuslist: lst inflates past %d bytes", jose.ErrMalformed, maxListBytes)
	}
	return &List{bits: bits, b: b}, nil
}
