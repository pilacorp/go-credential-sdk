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

func TestParseProof(t *testing.T) {
	a, b := mkLeaf(0x01), mkLeaf(0x02)
	proof, err := parseProof([]string{
		"0x" + hex.EncodeToString(a[:]),
		"0x" + hex.EncodeToString(b[:]),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(proof) != 2 || proof[0] != a || proof[1] != b {
		t.Fatalf("parseProof mismatch: %x", proof)
	}

	if _, err := parseProof([]string{"0xzz"}); err == nil {
		t.Fatal("expected error for malformed proof element")
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
