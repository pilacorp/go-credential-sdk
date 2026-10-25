package statuslist

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/pilacorp/go-credential-sdk/jose"
)

// The examples of draft-ietf-oauth-status-list-21 §4.1 and §4.2: status[i]
// as the draft lists it, the byte array, and the lst of the JSON encoding.
// Go's zlib does not reproduce the draft's compressed bytes, so Encode is
// checked by decoding its output, not by comparing it with lst.
func TestDraft21Section42Examples(t *testing.T) {
	tests := []struct {
		name   string
		bits   int
		lst    string
		bytes  []byte
		status []uint8
	}{
		{"bits=1", 1, "eNrbuRgAAhcBXQ", []byte{0xb9, 0xa3},
			[]uint8{1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1}},
		{"bits=2", 2, "eNo76fITAAPfAgc", []byte{0xc9, 0x44, 0xf9},
			[]uint8{1, 2, 0, 3, 0, 1, 0, 1, 1, 2, 3, 3}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l, err := Decode(tt.lst, tt.bits)
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			if got := l.Bytes(); !bytes.Equal(got, tt.bytes) {
				t.Fatalf("Bytes = %x, want %x", got, tt.bytes)
			}
			for i, want := range tt.status {
				if got, err := l.Get(i); err != nil || got != want {
					t.Errorf("Get(%d) = %d, %v; want %d", i, got, err, want)
				}
			}

			l, err = FromBytes(tt.bytes, tt.bits)
			if err != nil {
				t.Fatalf("FromBytes: %v", err)
			}
			lst, err := l.Encode()
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}
			back, err := Decode(lst, tt.bits)
			if err != nil {
				t.Fatalf("Decode(Encode): %v", err)
			}
			if got := back.Bytes(); !bytes.Equal(got, tt.bytes) {
				t.Fatalf("Decode(Encode) = %x, want %x", got, tt.bytes)
			}
		})
	}
}

// Entry 917 set to the largest value and then to 1, located by hand from
// draft 21 §4.1 step 3 (blocks packed from the least significant bit): with b
// bits an entry, a byte holds 8/b entries, so entry 917 is in byte 917/(8/b)
// at bit (917 mod (8/b))·b. Setting 1 must clear the other bits of the entry.
func TestDraft21Section41Index917(t *testing.T) {
	tests := []struct {
		bits      int
		byteIndex int
		byteValue byte // entry 917 = 1
	}{
		{1, 114, 0b0010_0000}, // 917 = 114·8 + 5
		{2, 229, 0b0000_0100}, // 917 = 229·4 + 1, bits 2–3
		{4, 458, 0b0001_0000}, // 917 = 458·2 + 1, bits 4–7
		{8, 917, 0b0000_0001},
	}
	for _, tt := range tests {
		l, err := New(1024, tt.bits)
		if err != nil {
			t.Fatalf("bits=%d: New: %v", tt.bits, err)
		}
		if err := l.Set(917, uint8(1<<tt.bits-1)); err != nil {
			t.Fatalf("bits=%d: Set: %v", tt.bits, err)
		}
		if err := l.Set(917, 1); err != nil {
			t.Fatalf("bits=%d: Set: %v", tt.bits, err)
		}
		want := make([]byte, 1024*tt.bits/8)
		want[tt.byteIndex] = tt.byteValue
		if got := l.Bytes(); !bytes.Equal(got, want) {
			t.Errorf("bits=%d: byte %d = %08b, want only byte %d = %08b", tt.bits, tt.byteIndex, got[tt.byteIndex], tt.byteIndex, tt.byteValue)
		}
		for i, v := range map[int]uint8{916: 0, 917: 1, 918: 0} {
			if got, err := l.Get(i); err != nil || got != v {
				t.Errorf("bits=%d: Get(%d) = %d, %v; want %d", tt.bits, i, got, err, v)
			}
		}
	}
}

type appendixCVector struct {
	name   string
	bits   int
	status map[int]uint8 // entries the draft lists; every other entry is 0
	lst    string
}

// The test vectors of draft 21 Appendix C, copied from the draft (C.4 from
// testdata): 2^20 entries, each listed entry with its value and every other
// entry 0. Encode is checked by decoding its output, as Go's zlib writes other
// bytes than the draft's.
func TestDraft21AppendixC(t *testing.T) {
	tests := []appendixCVector{
		{"C.1", 1, map[int]uint8{0: 0b1, 1993: 0b1, 25460: 0b1, 159495: 0b1, 495669: 0b1, 554353: 0b1, 645645: 0b1, 723232: 0b1, 854545: 0b1, 934534: 0b1, 1000345: 0b1},
			"eNrt3AENwCAMAEGogklACtKQPg9LugC9k_ACvreiogE" +
				"AAKkeCQAAAAAAAAAAAAAAAAAAAIBylgQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
				"AAAAAAAAAAAAAAAAAAAXG9IAAAAAAAAAPwsJAAAAAAAAAAAAAAAvhsSAAAAAAAAAAA" +
				"A7KpLAAAAAAAAAAAAAAAAAAAAAJsLCQAAAAAAAAAAADjelAAAAAAAAAAAKjDMAQAAA" +
				"ACAZC8L2AEb"},
		{"C.2", 2, map[int]uint8{0: 0b01, 1993: 0b10, 25460: 0b01, 159495: 0b11, 495669: 0b01, 554353: 0b01, 645645: 0b10, 723232: 0b01, 854545: 0b01, 934534: 0b10, 1000345: 0b11},
			"eNrt2zENACEQAEEuoaBABP5VIO01fCjIHTMStt9ovGV" +
				"IAAAAAABAbiEBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEB5WwIAAAAAA" +
				"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
				"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAID0ugQAAAAAAAAAAAAAAAAAQG12SgAAA" +
				"AAAAAAAAAAAAAAAAAAAAAAAAOCSIQEAAAAAAAAAAAAAAAAAAAAAAAD8ExIAAAAAAAA" +
				"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwJEuAQAAAAAAAAAAAAAAAAAAAAAAAMB9S" +
				"wIAAAAAAAAAAAAAAAAAAACoYUoAAAAAAAAAAAAAAEBqH81gAQw"},
		{"C.3", 4, map[int]uint8{0: 0b0001, 1993: 0b0010, 35460: 0b0011, 459495: 0b0100, 595669: 0b0101, 754353: 0b0110, 845645: 0b0111, 923232: 0b1000, 924445: 0b1001, 934534: 0b1010, 1004534: 0b1011, 1000345: 0b1100, 1030203: 0b1101, 1030204: 0b1110, 1030205: 0b1111},
			"eNrt0EENgDAQADAIHwImkIIEJEwCUpCEBBQRHOy35Li" +
				"1EjoOQGabAgAAAAAAAAAAAAAAAAAAACC1SQEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
				"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
				"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
				"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
				"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABADrsCAAAAAAAAAAAAAAAAA" +
				"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
				"AAADoxaEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
				"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIIoCgAAAAAAAAAAAAAAAAA" +
				"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACArpwKAAAAAAAAAAAAAAAAAAAAA" +
				"AAAAAAAAAAAAAAAAAAAAAAAAAAAAGhqVkAzlwIAAAAAiGVRAAAAAAAAAAAAAAAAAAA" +
				"AAAAAAAAAAAAAAAAAAAAAAABx3AoAgLpVAQAAAAAAAAAAAAAAwM89rwMAAAAAAAAAA" +
				"AjsA9xMBMA"},
		draft21C4(t),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l, err := Decode(tt.lst, tt.bits)
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			if got, want := len(l.Bytes()), (1<<20)*tt.bits/8; got != want {
				t.Fatalf("%d bytes, want %d (2^20 entries)", got, want)
			}
			for i := range 1 << 20 {
				if got, err := l.Get(i); err != nil || got != tt.status[i] {
					t.Fatalf("Get(%d) = %d, %v; want %d", i, got, err, tt.status[i])
				}
			}
			lst, err := l.Encode()
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}
			back, err := Decode(lst, tt.bits)
			if err != nil || !bytes.Equal(back.Bytes(), l.Bytes()) {
				t.Fatalf("Decode(Encode) differs: %v", err)
			}
		})
	}
}

// draft21C4 reads Appendix C.4: its "status[i] = 0bv" lines, then the lines
// of its lst.
func draft21C4(t *testing.T) appendixCVector {
	t.Helper()
	raw, err := os.ReadFile("testdata/draft21-appendix-c4.txt")
	if err != nil {
		t.Fatal(err)
	}
	v := appendixCVector{name: "C.4", bits: 8, status: map[int]uint8{}}
	var lst strings.Builder
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		switch {
		case strings.HasPrefix(line, "#"):
		case strings.HasPrefix(line, "status["):
			var i int
			var s uint8
			if _, err := fmt.Sscanf(line, "status[%d] = 0b%b", &i, &s); err != nil {
				t.Fatalf("%q: %v", line, err)
			}
			v.status[i] = s
		default:
			lst.WriteString(line)
		}
	}
	if len(v.status) != 256 {
		t.Fatalf("C.4 lists %d entries, want 256", len(v.status))
	}
	v.lst = lst.String()
	return v
}

// Decode refuses a preset dictionary, a bad Adler-32 and an lst that inflates
// past 16 MiB, and accepts exactly 16 MiB. The inputs are built with
// compress/zlib and the draft 21 §4.1 bytes, not with Encode.
func TestDecodeRejects(t *testing.T) {
	draft := mustHex(t, "78dadbb918000217015d") // draft 21 §4.1, bits=1, [0xb9, 0xa3]
	badAdler := append([]byte(nil), draft...)
	badAdler[len(badAdler)-1] ^= 1
	tests := []struct {
		name string
		raw  []byte
	}{
		// FLG 0xf9 sets FDICT; DICTID 00000001 is the Adler-32 of an empty
		// dictionary, which compress/zlib accepts.
		{"preset dictionary", mustHex(t, "78f900000001dab918100000ffff0217015d")},
		{"bad Adler-32", badAdler},
		{"inflates past 16 MiB", deflate(t, make([]byte, 16<<20+1))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Decode(base64.RawURLEncoding.EncodeToString(tt.raw), 1)
			if !errors.Is(err, jose.ErrMalformed) {
				t.Fatalf("Decode = %v, want jose.ErrMalformed", err)
			}
		})
	}

	l, err := Decode(base64.RawURLEncoding.EncodeToString(deflate(t, make([]byte, 16<<20))), 1)
	if err != nil {
		t.Fatalf("Decode of exactly 16 MiB: %v", err)
	}
	if got := len(l.Bytes()); got != 16<<20 {
		t.Fatalf("Decode of exactly 16 MiB gave %d bytes", got)
	}
}

// A 1 GiB inflate bomb (about 7.3 MiB of ZLIB) must be cut at the 16 MiB cap
// while inflating, not after: reading it whole allocates at least 1 GiB,
// reading to the cap well under 512 MiB. No test in this package runs in
// parallel, so TotalAlloc counts Decode alone. The stream is written by hand,
// since compressing 1 GiB with compress/zlib is slow, far slower under -race.
func TestDecodeInflateBudget(t *testing.T) {
	// RFC 1951: a stored block holding one 0x00 (§3.2.4), then a
	// fixed-Huffman block (§3.2.6) of six copies of <length 258 (code 285,
	// 11000101), distance 1 (code 00000)> and end of block (0000000), 88 bits
	// that repeat byte-aligned; last, an empty final stored block.
	const reps = 1<<30/1548 + 1 // 1548 = 6·258 bytes a block
	const n = 1 + 1548*reps
	raw := append([]byte{0x78, 0x01, 0x00, 0x01, 0x00, 0xfe, 0xff, 0x00},
		bytes.Repeat(mustHex(t, "1a05a360148c8251300a00"), reps)...)
	raw = append(raw, 0x01, 0x00, 0x00, 0xff, 0xff)
	// ADLER32 (RFC 1950 §2.2) of n zeros: s1 stays 1, s2 adds 1 per byte.
	raw = binary.BigEndian.AppendUint32(raw, n%65521<<16|1)
	lst := base64.RawURLEncoding.EncodeToString(raw)

	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err := Decode(lst, 1)
	runtime.ReadMemStats(&after)
	if !errors.Is(err, jose.ErrMalformed) || !strings.Contains(err.Error(), "inflates past") {
		t.Fatalf("Decode = %v, want the size error", err)
	}
	if grew := after.TotalAlloc - before.TotalAlloc; grew >= 512<<20 {
		t.Fatalf("Decode allocated %d MiB, want under 512 MiB", grew>>20)
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func deflate(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	if _, err := w.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
