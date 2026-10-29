// Package statuslist implements the Status List and the Status List Token in
// JWT format of Token Status List, draft-ietf-oauth-status-list-21: the byte
// array and its encoding (§4.1, §4.2), status values (§7), signing the token
// (§5.1), and reading the status of a Referenced Token from a fetched token
// (Checker, §8).
//
// Malformed input to Decode wraps jose.ErrMalformed; a caller mistake (an
// index or value out of range, a list not made by this package, missing
// claims) wraps jose.ErrInvalidArgument; SignToken wraps the jose/jws errors
// unchanged, so a nil key gives jose.ErrInvalidArgument or jws.ErrBadKey and
// a signer holding another key gives jws.ErrSelfCheck. Every error of
// Checker.Status means no statement about the status can be made (§8.3);
// there an index outside a fetched list wraps ErrIndexOutOfBounds, the one
// sentinel of this package: the Referenced Token MUST be rejected
// (draft-ietf-oauth-status-list-21 §8.3 step 6), and the caller made no
// mistake.
//
// A List is not safe for concurrent use while Set runs; a Checker is.
package statuslist

import (
	"errors"
	"fmt"

	"github.com/pilacorp/go-credential-sdk/jose"
)

// ErrIndexOutOfBounds: Checker.Status wraps it when the index of the
// Referenced Token is outside the fetched Status List:
// draft-ietf-oauth-status-list-21 §8.3 step 6 says that token MUST be
// rejected, while other failures of Status SHOULD be (§8.3). It is not
// jose.ErrInvalidArgument: the index comes from the token. The same cached
// list gives the same answer.
var ErrIndexOutOfBounds = errors.New("statuslist: index out of bounds")

// maxListBytes caps the byte array of a list. New and FromBytes refuse a
// larger one, which bounds what they allocate and what Encode and SignToken
// compress and sign; Decode refuses to inflate past it, which bounds a
// reader. Draft 21 sets no limit (§13.4); without one, zeros compress about
// 1000:1 and the lst of a 1 MiB token inflates to hundreds of MiB.
const maxListBytes = 16 << 20

// List is a Status List (draft 21 §4.1): entries of bits bits each,
// len·8/bits of them, packed into bytes. Make one with New, FromBytes or
// Decode; Get, Set, Encode and SignToken refuse the zero List, and its Bytes
// are nil.
type List struct {
	bits int
	b    []byte
}

// validBits: draft 21 §4.1 step 1, bits is 1, 2, 4 or 8, so an entry never
// spans two bytes.
func validBits(bits int) bool {
	return bits == 1 || bits == 2 || bits == 4 || bits == 8
}

// New returns a list of at least size entries of bits bits each, all 0
// (VALID, draft 21 §7.1). Its byte array is ceil(size·bits/8) bytes (§4.1
// step 2), and the list holds every entry those bytes carry, as Decode reads
// it back; a size·bits divisible by 8 (§13.4: RECOMMENDED) gives exactly
// size. size may be 0, since §4.1 step 2 sets no minimum: the list then
// holds no entries. bits must be 1, 2, 4 or 8, and the byte array at most
// 16 MiB. A list over about 576 KiB fits the 1 MiB token a Checker reads
// only while it compresses well; size or split lists for the highest status
// change rate expected (draft 21 §13.4, Appendix B).
func New(size, bits int) (*List, error) {
	if !validBits(bits) {
		return nil, fmt.Errorf("%w: statuslist: bits %d, want 1, 2, 4 or 8", jose.ErrInvalidArgument, bits)
	}
	// Compared before multiplying, so size·bits cannot overflow.
	if size < 0 || size > maxListBytes*8/bits {
		return nil, fmt.Errorf("%w: statuslist: size %d out of range for %d-bit entries", jose.ErrInvalidArgument, size, bits)
	}
	return &List{bits: bits, b: make([]byte, (size*bits+7)/8)}, nil
}

// FromBytes returns a list over a copy of b, a byte array kept elsewhere (a
// database, a ledger) with entries of bits bits each; it holds len(b)·8/bits
// entries. b holds at most 16 MiB; an empty b is a list with no entries.
func FromBytes(b []byte, bits int) (*List, error) {
	if !validBits(bits) {
		return nil, fmt.Errorf("%w: statuslist: bits %d, want 1, 2, 4 or 8", jose.ErrInvalidArgument, bits)
	}
	if len(b) > maxListBytes {
		return nil, fmt.Errorf("%w: statuslist: %d bytes, want at most %d", jose.ErrInvalidArgument, len(b), maxListBytes)
	}
	return &List{bits: bits, b: append([]byte{}, b...)}, nil
}

func (l *List) valid() bool {
	return l != nil && l.bits != 0
}

// position is the one place that locates entry i. Draft 21 §4.1 step 3 and
// §11.1: entries are packed from the least significant bit of each byte, and
// bytes follow in their natural order, so entry i of a 1-bit list is bit
// i mod 8 of byte i/8.
func (l *List) position(i int) (byteIndex int, shift uint, err error) {
	if !l.valid() {
		return 0, 0, fmt.Errorf("%w: statuslist: list not made by New, FromBytes or Decode", jose.ErrInvalidArgument)
	}
	if n := l.entries(); i < 0 || i >= n {
		return 0, 0, fmt.Errorf("%w: statuslist: index %d outside [0, %d)", jose.ErrInvalidArgument, i, n)
	}
	perByte := 8 / l.bits
	return i / perByte, uint(i%perByte) * uint(l.bits), nil
}

// Get returns the status value of entry i (draft 21 §7). An index outside the
// list is an error: §8.3 step 6 says no statement about its status can be
// made.
func (l *List) Get(i int) (uint8, error) {
	at, shift, err := l.position(i)
	if err != nil {
		return 0, err
	}
	return l.b[at] >> shift & l.mask(), nil
}

// Set writes status value v for entry i. v must fit in the list's bits (draft
// 21 §7: the whole bits describe one value).
func (l *List) Set(i int, v uint8) error {
	at, shift, err := l.position(i)
	if err != nil {
		return err
	}
	if v > l.mask() {
		return fmt.Errorf("%w: statuslist: value %d does not fit in %d bits", jose.ErrInvalidArgument, v, l.bits)
	}
	l.b[at] = l.b[at]&^(l.mask()<<shift) | v<<shift
	return nil
}

// entries is the number of entries in a valid list.
func (l *List) entries() int {
	return len(l.b) * 8 / l.bits
}

func (l *List) mask() uint8 {
	return uint8(1<<l.bits - 1)
}

// Bytes returns a copy of the uncompressed byte array (draft 21 §4.1 step 2),
// the bytes Decode yields from the lst Encode writes; nil only for the zero
// List, and empty for a list with no entries.
func (l *List) Bytes() []byte {
	if !l.valid() {
		return nil
	}
	return append([]byte{}, l.b...)
}
