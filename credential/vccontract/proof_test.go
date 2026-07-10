package vccontract

import (
	"encoding/hex"
	"testing"
)

// mkLeaf builds a 32-byte value with every byte set to b, for readable fixtures.
func mkLeaf(b byte) [32]byte {
	var l [32]byte
	for i := range l {
		l[i] = b
	}
	return l
}

func TestComputeRoot_SingleLeaf(t *testing.T) {
	l := mkLeaf(0x11)
	if got := computeRoot(l, nil); got != l {
		t.Fatalf("single-leaf root must equal the leaf; got %x want %x", got, l)
	}
}

// TestComputeRoot_KnownAnswer checks the fold against a precomputed keccak256
// sorted-pair root for a 3-leaf tree (leaves 0x01.., 0x02.., 0x03..):
//
//	p01  = keccak256(sort(l0, l1))
//	root = keccak256(sort(p01, l2))
//
// The expected root is a known-answer vector independent of this implementation.
func TestComputeRoot_KnownAnswer(t *testing.T) {
	l0, l1, l2 := mkLeaf(0x01), mkLeaf(0x02), mkLeaf(0x03)

	const wantHex = "1d614fa3c8de62938b0948972494f9a3858575db69ce1d34c77926f30732c981"

	// Proof for l0 is the ordered siblings [l1, l2].
	got := computeRoot(l0, [][32]byte{l1, l2})

	if hex.EncodeToString(got[:]) != wantHex {
		t.Fatalf("computeRoot mismatch:\n got  %x\n want %s", got, wantHex)
	}
}

func TestComputeRoot_OrderInsensitiveWithinPair(t *testing.T) {
	// Because pairs are sorted before hashing, swapping the leaf and its sole
	// sibling must yield the same parent.
	a, b := mkLeaf(0xaa), mkLeaf(0xbb)
	if computeRoot(a, [][32]byte{b}) != computeRoot(b, [][32]byte{a}) {
		t.Fatal("sorted-pair hashing must be order-insensitive within a pair")
	}
}

func TestHexToBytes32(t *testing.T) {
	want := mkLeaf(0xcd)
	hexStr := "0x" + hex.EncodeToString(want[:])

	got, err := hexToBytes32(hexStr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != want {
		t.Fatalf("hexToBytes32 mismatch: got %x want %x", got, want)
	}

	if _, err := hexToBytes32("0x1234"); err == nil {
		t.Fatal("expected error for short hex input")
	}
}

func TestVerifyRequestValidate(t *testing.T) {
	leafBytes := mkLeaf(0x01)
	siblingBytes := mkLeaf(0x02)

	valid := &VerifyRequest{
		IssuerAddress: "0x1111111111111111111111111111111111111111",
		TreeIndex:     0,
		Leaf:          "0x" + hex.EncodeToString(leafBytes[:]),
		Proof:         []string{"0x" + hex.EncodeToString(siblingBytes[:])},
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}

	bad := *valid
	bad.IssuerAddress = "not-an-address"
	if err := bad.Validate(); err == nil {
		t.Fatal("expected error for invalid issuer address")
	}

	badLeaf := *valid
	badLeaf.Leaf = "0xabcd"
	if err := badLeaf.Validate(); err == nil {
		t.Fatal("expected error for malformed leaf")
	}
}
