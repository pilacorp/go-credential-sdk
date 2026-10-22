// Bit reading follows byteAndBitPosition and readStatusByte in
// eudi-lib-kmp-statium, lib/src/commonMain/kotlin/eu/europa/ec/eudi/statium/ReadStatus.kt
// (commit 118171ff25c4dcd8f74e6f30ceb58f245ec3ea4e, Apache-2.0), rewritten in
// Go and re-checked against Token Status List draft 21 §4.1. Building and
// writing are written from scratch from draft 21 §4.

package statuslist

import "fmt"

// DefaultMaxListBytes is the largest raw list New and FromBytes build, and the
// default inflate limit of Decode and Checker: a list a verifier with default
// settings would refuse is refused when it is built.
const DefaultMaxListBytes = 16 << 20

// List is a Token Status List: size entries of bits bits each, packed into
// bytes least-significant bit first (draft 21 §4.1). Bytes() is exactly the
// inflated lst of a token and the bytes anchored on chain.
//
// A List is not safe for concurrent writes.
type List struct {
	bits int
	size int
	data []byte
}

func validBits(bits int) bool {
	return bits == 1 || bits == 2 || bits == 4 || bits == 8
}

// New returns a list of size entries of bits bits, all 0. size must be > 0,
// bits one of 1, 2, 4, 8; the list takes ceil(size·bits/8) bytes.
func New(size, bits int) (*List, error) {
	if !validBits(bits) {
		return nil, fmt.Errorf("%w: bits %d, want 1, 2, 4 or 8", ErrInvalidArgument, bits)
	}
	if size <= 0 {
		return nil, fmt.Errorf("%w: size %d, want > 0", ErrInvalidArgument, size)
	}
	if size > DefaultMaxListBytes*(8/bits) {
		return nil, fmt.Errorf("%w: %d entries of %d bits exceed %d bytes", ErrTooLarge, size, bits, DefaultMaxListBytes)
	}
	return &List{bits: bits, size: size, data: make([]byte, (size*bits+7)/8)}, nil
}

// FromBytes returns a list over a copy of b (bytes kept in a database, or read
// from the chain); its size is len(b)·8/bits. b must not be empty.
func FromBytes(b []byte, bits int) (*List, error) {
	if !validBits(bits) {
		return nil, fmt.Errorf("%w: bits %d, want 1, 2, 4 or 8", ErrInvalidArgument, bits)
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("%w: empty list", ErrInvalidArgument)
	}
	if len(b) > DefaultMaxListBytes {
		return nil, fmt.Errorf("%w: %d bytes exceed %d", ErrTooLarge, len(b), DefaultMaxListBytes)
	}
	return &List{bits: bits, size: len(b) * 8 / bits, data: append([]byte(nil), b...)}, nil
}

// Bits returns the number of bits per entry.
func (l *List) Bits() int { return l.bits }

// Size returns the number of entries.
func (l *List) Size() int { return l.size }

// Bytes returns a copy of the raw (not compressed) bytes.
func (l *List) Bytes() []byte { return append([]byte(nil), l.data...) }

// position returns the byte holding entry i and the shift of its lowest bit:
// byte i/(8/bits), bit (i mod (8/bits))·bits counted from the least
// significant bit. With bits = 1, entry 917 is byte 114, bit 5; with bits = 2,
// byte 229, bits 2–3.
func (l *List) position(i int) (int, uint, error) {
	if i < 0 || i >= l.size {
		return 0, 0, fmt.Errorf("%w: %d, list has %d entries", ErrIndexOutOfRange, i, l.size)
	}
	perByte := 8 / l.bits
	return i / perByte, uint((i % perByte) * l.bits), nil
}

func (l *List) mask() byte { return byte(1<<l.bits - 1) }

// Get returns entry i. 0 ≤ i < Size(), else ErrIndexOutOfRange.
func (l *List) Get(i int) (byte, error) {
	at, shift, err := l.position(i)
	if err != nil {
		return 0, err
	}
	return l.data[at] >> shift & l.mask(), nil
}

// Set writes v to entry i. 0 ≤ i < Size(), else ErrIndexOutOfRange; v must fit
// in bits bits (v < 2^bits), else ErrInvalidArgument.
func (l *List) Set(i int, v byte) error {
	at, shift, err := l.position(i)
	if err != nil {
		return err
	}
	if v&^l.mask() != 0 {
		return fmt.Errorf("%w: value %#x does not fit in %d bits", ErrInvalidArgument, v, l.bits)
	}
	l.data[at] = l.data[at]&^(l.mask()<<shift) | v<<shift
	return nil
}
