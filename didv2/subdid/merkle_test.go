package subdid

import (
	"bytes"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func fixtureLeaves(n int) [][32]byte {
	leaves := make([][32]byte, n)
	for i := range leaves {
		copy(leaves[i][:], bytes.Repeat([]byte{byte(i + 1)}, 32))
	}

	return leaves
}

func hash32(t *testing.T, s string) [32]byte {
	t.Helper()

	b := common.FromHex(s)
	if len(b) != 32 {
		t.Fatalf("fixture %s is %d bytes", s, len(b))
	}

	return [32]byte(b)
}

func TestMerkleRoot_Vectors(t *testing.T) {
	tests := []struct {
		n    int
		root string
	}{
		{1, "0x0101010101010101010101010101010101010101010101010101010101010101"},
		{2, "0x346d8c96a2454213fcc0daff3c96ad0398148181b9fa6488f7ae2c0af5b20aa0"},
		{3, "0x1d614fa3c8de62938b0948972494f9a3858575db69ce1d34c77926f30732c981"},
		{5, "0x55d458ff264cc10cb4ef71d27a18db86f587999b2355cfa5eb5fccf8c973bced"},
	}
	for _, tt := range tests {
		got, err := MerkleRoot(fixtureLeaves(tt.n))
		if err != nil {
			t.Fatalf("n=%d: %v", tt.n, err)
		}
		if got != hash32(t, tt.root) {
			t.Errorf("n=%d: root = %x, want %s", tt.n, got, tt.root)
		}
	}
}

func TestMerkleProof_Vectors(t *testing.T) {
	tests := []struct {
		index int
		proof []string
	}{
		{4, []string{"0x0b242b9a6559f2d9f8563485a0697b746ec58ce879e0e5ac94d4c8a250723121"}},
		{2, []string{
			"0x0404040404040404040404040404040404040404040404040404040404040404",
			"0x346d8c96a2454213fcc0daff3c96ad0398148181b9fa6488f7ae2c0af5b20aa0",
			"0x0505050505050505050505050505050505050505050505050505050505050505",
		}},
	}
	for _, tt := range tests {
		got, err := MerkleProof(fixtureLeaves(5), tt.index)
		if err != nil {
			t.Fatalf("index %d: %v", tt.index, err)
		}
		if len(got) != len(tt.proof) {
			t.Fatalf("index %d: proof has %d siblings, want %d", tt.index, len(got), len(tt.proof))
		}
		for i := range got {
			if got[i] != hash32(t, tt.proof[i]) {
				t.Errorf("index %d: sibling %d = %x, want %s", tt.index, i, got[i], tt.proof[i])
			}
		}
	}
}

func TestRevokedLeaf_Vectors(t *testing.T) {
	tests := []struct{ addr, leaf string }{
		{"0x86b2efd244acb31eb238a65ca05476ab42558071", "0x83c91d2020210e4924defde940dcb4e63ec3f20bbad4229da6019faba05cc206"},
		{"0x5b6a5525e2c2d2428554b04d24b3bb5c1f3f5ae3", "0xa0fed93a6a92b69bcbc4e8f5983d5ede26eef742274c3700b5e400a4c8856c3d"},
	}
	for _, tt := range tests {
		if got := RevokedLeaf(common.HexToAddress(tt.addr)); got != hash32(t, tt.leaf) {
			t.Errorf("RevokedLeaf(%s) = %x, want %s", tt.addr, got, tt.leaf)
		}
	}

	leaves := fixtureLeaves(3)
	leaves[2] = RevokedLeaf(common.HexToAddress("0x86b2efd244acb31eb238a65ca05476ab42558071"))
	root, err := MerkleRoot(leaves)
	if err != nil {
		t.Fatal(err)
	}
	if want := hash32(t, "0x934b02ce8ddedb479ffc1fad0eaf40f0cd0d75e853f9d28e9b1273fd49004993"); root != want {
		t.Errorf("n=3 with a revoked leaf: root = %x, want %x", root, want)
	}
}

func TestMerkleProof_EveryLeafVerifies(t *testing.T) {
	for n := 1; n <= 9; n++ {
		leaves := fixtureLeaves(n)
		root, err := MerkleRoot(leaves)
		if err != nil {
			t.Fatalf("n=%d: %v", n, err)
		}
		for i := range leaves {
			proof, err := MerkleProof(leaves, i)
			if err != nil {
				t.Fatalf("n=%d index %d: %v", n, i, err)
			}
			if n == 1 && len(proof) != 0 {
				t.Errorf("n=1: proof has %d siblings, want none", len(proof))
			}
			if !VerifyProof(leaves[i], proof, root) {
				t.Errorf("n=%d index %d: proof does not verify", n, i)
			}
			if len(proof) > 0 {
				changed := append([][32]byte(nil), proof...)
				changed[len(changed)-1][0] ^= 0xff
				if VerifyProof(leaves[i], changed, root) {
					t.Errorf("n=%d index %d: a changed sibling still verifies", n, i)
				}
			}
		}
	}
}
