package statuslist

import (
	"math"
	"testing"
)

func TestChainListID(t *testing.T) {
	for _, tc := range []struct {
		bits int
		id   uint64
		want string
	}{
		{1, 7, "dc-b1-7"}, {2, 15, "dc-b2-15"}, {4, 0, "dc-b4-0"}, {8, math.MaxUint64, "dc-b8-18446744073709551615"},
	} {
		got, err := ChainListID(tc.bits, tc.id)
		if err != nil || got != tc.want {
			t.Errorf("ChainListID(%d, %d) = %q, %v; want %q", tc.bits, tc.id, got, err, tc.want)
		}
		bits, id, err := ParseChainListID(got)
		if err != nil || bits != tc.bits || id != tc.id {
			t.Errorf("ParseChainListID(%q) = %d, %d, %v", got, bits, id, err)
		}
	}
	for _, bits := range []int{0, 3, 16, -1} {
		if _, err := ChainListID(bits, 1); err == nil {
			t.Errorf("ChainListID(%d, 1) accepted", bits)
		} else {
			wantErr(t, err, ErrInvalidArgument)
		}
	}
}

func TestParseChainListIDRejects(t *testing.T) {
	for _, s := range []string{
		"", "7", "dc-b1-", "dc-b1", "dc-b3-1", "dc-b0-1", "dc-b16-1", "dc-b1-07", "dc-b1-00", "dc-b1-+7", "dc-b1--7",
		"dc-b1-7 ", " dc-b1-7", "DC-b1-7", "dc-B1-7", "dc-b1_7", "dc-b1-7a", "dc-b1-0x7", "dc-b1-18446744073709551616",
		"vc-b1-7", "dc-b1-٣", "dc-b1-1_000", "dc-b1-0b1", "dc-b1-1e3",
	} {
		if bits, id, err := ParseChainListID(s); err == nil {
			t.Errorf("ParseChainListID(%q) = %d, %d, accepted", s, bits, id)
		} else {
			wantErr(t, err, ErrMalformed)
		}
	}
}
