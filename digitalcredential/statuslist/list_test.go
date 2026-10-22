package statuslist

import (
	"bytes"
	"testing"
)

func TestNewRules(t *testing.T) {
	for _, tc := range []struct{ size, bits int }{{1, 0}, {1, 3}, {1, 5}, {1, 16}, {1, -1}, {0, 1}, {-1, 1}} {
		if _, err := New(tc.size, tc.bits); err == nil {
			t.Errorf("New(%d, %d) accepted", tc.size, tc.bits)
		} else {
			wantErr(t, err, ErrInvalidArgument)
		}
	}
	for _, tc := range []struct{ size, bits, bytes int }{
		{1, 1, 1}, {8, 1, 1}, {9, 1, 2}, {4, 2, 1}, {5, 2, 2}, {3, 4, 2}, {2, 8, 2}, {16, 1, 2}, {12, 2, 3},
	} {
		l, err := New(tc.size, tc.bits)
		if err != nil {
			t.Fatal(err)
		}
		if got := l.Bytes(); len(got) != tc.bytes || !bytes.Equal(got, make([]byte, tc.bytes)) {
			t.Errorf("New(%d, %d).Bytes() = %x, want %d zero bytes", tc.size, tc.bits, got, tc.bytes)
		}
		if l.Size() != tc.size || l.Bits() != tc.bits {
			t.Errorf("New(%d, %d): Size %d, Bits %d", tc.size, tc.bits, l.Size(), l.Bits())
		}
	}
	if _, err := New(DefaultMaxListBytes*8+1, 1); err == nil {
		t.Error("a list over DefaultMaxListBytes was built")
	} else {
		wantErr(t, err, ErrTooLarge)
	}
	if _, err := New(DefaultMaxListBytes*8, 1); err != nil {
		t.Errorf("a list of exactly DefaultMaxListBytes: %v", err)
	}
}

func TestFromBytes(t *testing.T) {
	src := []byte{0xB9, 0xA3}
	for bits, size := range map[int]int{1: 16, 2: 8, 4: 4, 8: 2} {
		l, err := FromBytes(src, bits)
		if err != nil {
			t.Fatal(err)
		}
		if l.Size() != size {
			t.Errorf("FromBytes(2 bytes, %d).Size() = %d, want %d", bits, l.Size(), size)
		}
	}
	l, _ := FromBytes(src, 1)
	src[0] = 0
	if l.Bytes()[0] != 0xB9 {
		t.Error("FromBytes must copy its input")
	}
	b := l.Bytes()
	b[1] = 0
	if l.Bytes()[1] != 0xA3 {
		t.Error("Bytes must return a copy")
	}
	if _, err := FromBytes(nil, 1); err == nil {
		t.Error("an empty list was accepted")
	}
	if _, err := FromBytes([]byte{1}, 3); err == nil {
		t.Error("bits 3 was accepted")
	}
	if _, err := FromBytes(make([]byte, DefaultMaxListBytes+1), 1); err == nil {
		t.Error("a list over DefaultMaxListBytes was accepted")
	}
}

// TestDraftByteLayout builds the two lists of draft 21 §4.1 entry by entry and
// checks the exact bytes, then reads them back.
func TestDraftByteLayout(t *testing.T) {
	for _, tc := range []struct {
		bits   int
		values []byte
		bytes  []byte
	}{
		{1, []byte{1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1}, []byte{0xB9, 0xA3}},
		{2, []byte{1, 2, 0, 3, 0, 1, 0, 1, 1, 2, 3, 3}, []byte{0xC9, 0x44, 0xF9}},
	} {
		l, err := New(len(tc.values), tc.bits)
		if err != nil {
			t.Fatal(err)
		}
		for i, v := range tc.values {
			if err := l.Set(i, v); err != nil {
				t.Fatal(err)
			}
		}
		if !bytes.Equal(l.Bytes(), tc.bytes) {
			t.Errorf("bits %d: bytes %x, want %x", tc.bits, l.Bytes(), tc.bytes)
		}
		back, _ := FromBytes(tc.bytes, tc.bits)
		for i, want := range tc.values {
			if got, err := back.Get(i); err != nil || got != want {
				t.Errorf("bits %d: Get(%d) = %d, %v; want %d", tc.bits, i, got, err, want)
			}
		}
	}
}

// TestIndex917 is the worked example of the spec: entry 917 is byte 114 bit 5
// with bits = 1, byte 229 bits 2–3 with bits = 2.
func TestIndex917(t *testing.T) {
	l1 := mustList(t, 1000, 1, map[int]byte{917: 1})
	want1 := make([]byte, 125)
	want1[114] = 1 << 5
	if !bytes.Equal(l1.Bytes(), want1) {
		t.Errorf("bits 1: entry 917 is not byte 114 bit 5")
	}
	l2 := mustList(t, 1000, 2, map[int]byte{917: 0b11})
	want2 := make([]byte, 250)
	want2[229] = 0b11 << 2
	if !bytes.Equal(l2.Bytes(), want2) {
		t.Errorf("bits 2: entry 917 is not byte 229 bits 2-3")
	}
}

func TestSetGetRules(t *testing.T) {
	for _, bits := range []int{1, 2, 4, 8} {
		l := mustList(t, 10, bits, nil)
		for _, i := range []int{-1, 10, 1 << 40} {
			if _, err := l.Get(i); err == nil {
				t.Errorf("bits %d: Get(%d) accepted", bits, i)
			} else {
				wantErr(t, err, ErrIndexOutOfRange)
			}
			if err := l.Set(i, 0); err == nil {
				t.Errorf("bits %d: Set(%d) accepted", bits, i)
			} else {
				wantErr(t, err, ErrIndexOutOfRange)
			}
		}
		max := byte(1<<bits - 1)
		if err := l.Set(3, max); err != nil {
			t.Errorf("bits %d: Set(3, %#x): %v", bits, max, err)
		}
		if bits < 8 {
			if err := l.Set(3, max+1); err == nil {
				t.Errorf("bits %d: Set(3, %#x) accepted a value wider than bits", bits, max+1)
			} else {
				wantErr(t, err, ErrInvalidArgument)
			}
		}
	}
	// New(10, 1) has 16 bits of storage, but entries 10..15 are not part of
	// the list.
	l := mustList(t, 10, 1, nil)
	if _, err := l.Get(15); err == nil {
		t.Error("Get read the padding of the last byte")
	}
}

// TestSetKeepsNeighbours writes every entry with a pattern, overwrites each
// one and checks no other entry moved.
func TestSetKeepsNeighbours(t *testing.T) {
	for _, bits := range []int{1, 2, 4, 8} {
		const size = 64
		mask := byte(1<<bits - 1)
		l := mustList(t, size, bits, nil)
		want := make([]byte, size)
		for i := range want {
			want[i] = byte(i*7+3) & mask
			if err := l.Set(i, want[i]); err != nil {
				t.Fatal(err)
			}
		}
		for i := range want {
			want[i] = ^want[i] & mask
			if err := l.Set(i, want[i]); err != nil {
				t.Fatal(err)
			}
			for j := range want {
				if got, _ := l.Get(j); got != want[j] {
					t.Fatalf("bits %d: after Set(%d), Get(%d) = %d, want %d", bits, i, j, got, want[j])
				}
			}
		}
	}
}
