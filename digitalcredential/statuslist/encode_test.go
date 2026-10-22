package statuslist

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"encoding/json"
	"os"
	"strconv"
	"testing"

	"github.com/pilacorp/go-credential-sdk/jose"
)

// TestDecodeDraftExamples: the 1-bit and 2-bit lst of draft 21 §4.2 decode to
// the listed values.
func TestDecodeDraftExamples(t *testing.T) {
	for _, tc := range []struct {
		lst    string
		bits   int
		bytes  []byte
		values []byte
	}{
		{"eNrbuRgAAhcBXQ", 1, []byte{0xB9, 0xA3}, []byte{1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1}},
		{"eNo76fITAAPfAgc", 2, []byte{0xC9, 0x44, 0xF9}, []byte{1, 2, 0, 3, 0, 1, 0, 1, 1, 2, 3, 3}},
	} {
		l, err := Decode(tc.lst, tc.bits)
		if err != nil {
			t.Fatalf("Decode(%q): %v", tc.lst, err)
		}
		if !bytes.Equal(l.Bytes(), tc.bytes) {
			t.Errorf("Decode(%q) bytes %x, want %x", tc.lst, l.Bytes(), tc.bytes)
		}
		for i, want := range tc.values {
			if got, err := l.Get(i); err != nil || got != want {
				t.Errorf("Decode(%q).Get(%d) = %d, %v; want %d", tc.lst, i, got, err, want)
			}
		}
	}
}

// TestEncode: ZLIB with the best-compression header (0x78 0xDA, as in the
// draft's "compressed array" hex), checksum included, base64url without
// padding; Decode reverses it.
func TestEncode(t *testing.T) {
	l := mustList(t, 16, 1, map[int]byte{0: 1, 3: 1, 4: 1, 5: 1, 7: 1, 8: 1, 9: 1, 13: 1, 15: 1})
	lst, err := l.Encode()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := jose.DecodeSegment(lst)
	if err != nil {
		t.Fatalf("lst is not strict base64url without padding: %v", err)
	}
	if len(raw) < 6 || raw[0] != 0x78 || raw[1] != 0xDA {
		t.Fatalf("compressed %x, want a ZLIB header 78da (best compression)", raw)
	}
	inflated, err := zlibInflate(raw)
	if err != nil || !bytes.Equal(inflated, []byte{0xB9, 0xA3}) {
		t.Fatalf("inflate %x, %v", inflated, err)
	}
	back, err := Decode(lst, 1)
	if err != nil || !bytes.Equal(back.Bytes(), l.Bytes()) {
		t.Fatalf("Decode(Encode()) = %v, %v", back, err)
	}
}

func zlibInflate(b []byte) ([]byte, error) {
	z, err := zlib.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	_, err = out.ReadFrom(z)
	return out.Bytes(), err
}

// TestAppendixCVectors: the 2^20-entry vectors of draft 21 Appendix C, for 1,
// 2, 4 and 8 bits, decode to the listed values and 0 everywhere else.
func TestAppendixCVectors(t *testing.T) {
	raw, err := os.ReadFile("../testdata/statuslist/draft21-appendix-c.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Vectors []struct {
			Section  string
			Bits     int
			Size     int
			Lst      string
			Statuses map[string]byte
		}
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Vectors) != 4 {
		t.Fatalf("%d vectors, want 4", len(file.Vectors))
	}
	for _, v := range file.Vectors {
		l, err := Decode(v.Lst, v.Bits)
		if err != nil {
			t.Fatalf("%s: %v", v.Section, err)
		}
		if l.Size() != v.Size {
			t.Errorf("%s: size %d, want %d", v.Section, l.Size(), v.Size)
		}
		want := map[int]byte{}
		for k, s := range v.Statuses {
			i, _ := strconv.Atoi(k)
			want[i] = s
		}
		for i := 0; i < l.Size(); i++ {
			if got, _ := l.Get(i); got != want[i] {
				t.Fatalf("%s: entry %d = %d, want %d", v.Section, i, got, want[i])
			}
		}
		again, err := l.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if back, err := Decode(again, v.Bits); err != nil || !bytes.Equal(back.Bytes(), l.Bytes()) {
			t.Errorf("%s: Encode/Decode round trip changed the bytes", v.Section)
		}
	}
}

func deflateRaw(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.BestCompression)
	_, _ = w.Write(b)
	_ = w.Close()
	return buf.Bytes()
}

func zlibBytes(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, _ := zlib.NewWriterLevel(&buf, zlib.BestCompression)
	_, _ = w.Write(b)
	_ = w.Close()
	return buf.Bytes()
}

func TestDecodeTraps(t *testing.T) {
	good := zlibBytes(t, []byte{0xB9, 0xA3})
	badChecksum := bytes.Clone(good)
	badChecksum[len(badChecksum)-1] ^= 1
	var dict bytes.Buffer
	dw, _ := zlib.NewWriterLevelDict(&dict, zlib.BestCompression, []byte("dictionary"))
	_, _ = dw.Write([]byte{0xB9, 0xA3})
	_ = dw.Close()

	enc := jose.EncodeSegment
	for _, tc := range []struct {
		name string
		lst  string
		bits int
		want error
	}{
		{"padding", "eNrbuRgAAhcBXQ==", 1, ErrMalformed},
		{"line break", "eNrbuRgA\nAhcBXQ", 1, ErrMalformed},
		{"non-zero trailing bits", "eNrbuRgAAhcBXR", 1, ErrMalformed},
		{"standard alphabet", "eNo76fITAAPfAgc+", 2, ErrMalformed},
		{"raw DEFLATE without ZLIB header", enc(deflateRaw(t, []byte{0xB9, 0xA3})), 1, ErrMalformed},
		{"bad Adler-32 checksum", enc(badChecksum), 1, ErrMalformed},
		{"truncated stream", enc(good[:len(good)-2]), 1, ErrMalformed},
		{"bytes after the stream", enc(append(bytes.Clone(good), 0)), 1, ErrMalformed},
		{"preset dictionary", enc(dict.Bytes()), 1, ErrMalformed},
		{"empty list", enc(zlibBytes(t, nil)), 1, ErrMalformed},
		{"empty lst", "", 1, ErrMalformed},
		{"bits 3", "eNrbuRgAAhcBXQ", 3, ErrMalformed},
		{"bits 0", "eNrbuRgAAhcBXQ", 0, ErrMalformed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l, err := Decode(tc.lst, tc.bits)
			if l != nil {
				t.Fatal("a list was returned with the error")
			}
			wantErr(t, err, tc.want)
		})
	}
}

// TestInflateLimit: an lst that inflates past the limit is refused; exactly
// the limit is accepted. Decode applies DefaultMaxListBytes.
func TestInflateLimit(t *testing.T) {
	const limit = 1000
	at := jose.EncodeSegment(zlibBytes(t, make([]byte, limit)))
	over := jose.EncodeSegment(zlibBytes(t, make([]byte, limit+1)))
	if _, err := decode(at, 1, limit); err != nil {
		t.Errorf("exactly the limit: %v", err)
	}
	if _, err := decode(over, 1, limit); err == nil {
		t.Error("one byte over the limit was accepted")
	} else {
		wantErr(t, err, ErrTooLarge)
	}

	bomb := jose.EncodeSegment(zlibBytes(t, make([]byte, DefaultMaxListBytes+1)))
	if len(bomb) > 30<<10 {
		t.Fatalf("bomb lst is %d bytes; expected a few KB", len(bomb))
	}
	if _, err := Decode(bomb, 1); err == nil {
		t.Error("a 16 MB + 1 byte list was accepted by Decode")
	} else {
		wantErr(t, err, ErrTooLarge)
	}
}
