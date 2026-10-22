package statuslist

import (
	"bytes"
	"testing"
)

// FuzzDecode: Decode never panics, and a list it accepts has size
// len·8/bits and encodes back to the same bytes.
func FuzzDecode(f *testing.F) {
	f.Add("eNrbuRgAAhcBXQ", uint8(0))
	f.Add("eNo76fITAAPfAgc", uint8(1))
	f.Add("eNrbuRgAAhcBXR", uint8(2))
	f.Add("", uint8(3))
	f.Fuzz(func(t *testing.T, lst string, sel uint8) {
		bits := 1 << (sel % 4) // 1, 2, 4, 8; invalid widths are unit-tested
		l, err := decode(lst, bits, 1<<16)
		if err != nil {
			if l != nil {
				t.Fatal("list returned with an error")
			}
			return
		}
		if l.Size() != len(l.data)*8/bits || l.Size() == 0 {
			t.Fatalf("size %d for %d bytes of %d bits", l.Size(), len(l.data), bits)
		}
		again, err := l.Encode()
		if err != nil {
			t.Fatal(err)
		}
		back, err := decode(again, bits, 1<<16)
		if err != nil || !bytes.Equal(back.Bytes(), l.Bytes()) {
			t.Fatalf("round trip: %v", err)
		}
	})
}

// FuzzFromBytesGet: Get agrees with the draft 21 §4.1 formula, Set then Get
// returns the value, and Set touches no other entry.
func FuzzFromBytesGet(f *testing.F) {
	f.Add([]byte{0xB9, 0xA3}, uint8(0), 13, byte(1))
	f.Add([]byte{0xC9, 0x44, 0xF9}, uint8(1), 10, byte(2))
	f.Add([]byte{0xFF}, uint8(3), 0, byte(0))
	f.Fuzz(func(t *testing.T, b []byte, sel uint8, i int, v byte) {
		bits := 1 << (sel % 4)
		l, err := FromBytes(b, bits)
		if err != nil {
			return
		}
		got, err := l.Get(i)
		if i < 0 || i >= l.Size() {
			if err == nil {
				t.Fatalf("Get(%d) on %d entries accepted", i, l.Size())
			}
			return
		}
		perByte := 8 / bits
		want := b[i/perByte] >> ((i % perByte) * bits) & (1<<bits - 1)
		if err != nil || got != want {
			t.Fatalf("Get(%d) = %d, %v; want %d", i, got, err, want)
		}
		before := l.Bytes()
		if err := l.Set(i, v); err != nil {
			if int(v) < 1<<bits {
				t.Fatalf("Set(%d, %d): %v", i, v, err)
			}
			if !bytes.Equal(l.Bytes(), before) {
				t.Fatal("a refused Set changed the list")
			}
			return
		}
		if g, _ := l.Get(i); g != v {
			t.Fatalf("Set(%d, %d) then Get = %d", i, v, g)
		}
		for j := 0; j < l.Size(); j++ {
			if j == i {
				continue
			}
			x, _ := l.Get(j)
			y := before[j/perByte] >> ((j % perByte) * bits) & (1<<bits - 1)
			if x != y {
				t.Fatalf("Set(%d) changed entry %d", i, j)
			}
		}
	})
}

// FuzzParseChainListID: an accepted id is the one ChainListID writes.
func FuzzParseChainListID(f *testing.F) {
	for _, s := range []string{"dc-b1-7", "dc-b2-15", "dc-b8-18446744073709551615", "dc-b1-07", "dc-b3-1"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		bits, id, err := ParseChainListID(s)
		if err != nil {
			return
		}
		again, err := ChainListID(bits, id)
		if err != nil || again != s {
			t.Fatalf("ParseChainListID(%q) = %d, %d; ChainListID gives %q, %v", s, bits, id, again, err)
		}
	})
}
