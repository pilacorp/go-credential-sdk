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

func hexOf(b [32]byte) string {
	return "0x" + hex.EncodeToString(b[:])
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

func TestVerifyByTxRequestValidate(t *testing.T) {
	valid := &VerifyByTxRequest{
		IssuerAddress: "0x1111111111111111111111111111111111111111",
		TreeIndex:     0,
		Leaf:          hexOf(mkLeaf(0x01)),
		Proof:         []string{hexOf(mkLeaf(0x02))},
		TxHash:        hexOf(mkLeaf(0x03)),
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}

	badIssuer := *valid
	badIssuer.IssuerAddress = "not-an-address"
	if err := badIssuer.Validate(); err == nil {
		t.Fatal("expected error for invalid issuer address")
	}

	badTx := *valid
	badTx.TxHash = "0xabcd"
	if err := badTx.Validate(); err == nil {
		t.Fatal("expected error for malformed tx hash")
	}

	missingTx := *valid
	missingTx.TxHash = ""
	if err := missingTx.Validate(); err == nil {
		t.Fatal("expected error for empty tx hash")
	}
}

// TestVerifyMerkleProof builds a small tree with the same sorted-pair keccak256
// hashing the contract uses and checks each leaf's proof folds up to the root.
func TestVerifyMerkleProof(t *testing.T) {
	a, b, c, d := mkLeaf(0x0a), mkLeaf(0x0b), mkLeaf(0x0c), mkLeaf(0x0d)

	// A four-leaf tree: root = H(H(a,b), H(c,d)).
	ab := hashPair(a, b)
	cd := hashPair(c, d)
	root := hashPair(ab, cd)

	cases := []struct {
		name  string
		leaf  [32]byte
		proof [][32]byte
	}{
		{"leaf a", a, [][32]byte{b, cd}},
		{"leaf b", b, [][32]byte{a, cd}},
		{"leaf c", c, [][32]byte{d, ab}},
		{"leaf d", d, [][32]byte{c, ab}},
	}

	for _, tc := range cases {
		if !verifyMerkleProof(tc.leaf, tc.proof, root) {
			t.Fatalf("%s: valid proof rejected", tc.name)
		}

		// A wrong sibling must not verify.
		bad := append([][32]byte{}, tc.proof...)
		bad[0] = mkLeaf(0xff)
		if verifyMerkleProof(tc.leaf, bad, root) {
			t.Fatalf("%s: tampered proof accepted", tc.name)
		}
	}

	// Wrong leaf against a valid path must fail.
	if verifyMerkleProof(mkLeaf(0xee), [][32]byte{b, cd}, root) {
		t.Fatal("unexpected: wrong leaf accepted")
	}
}

// TestVerifyMerkleProofSingleLeaf covers a single-leaf tree, where the root
// equals the leaf and the proof is empty.
func TestVerifyMerkleProofSingleLeaf(t *testing.T) {
	leaf := mkLeaf(0x42)

	if !verifyMerkleProof(leaf, nil, leaf) {
		t.Fatal("single-leaf proof rejected")
	}

	if verifyMerkleProof(leaf, nil, mkLeaf(0x43)) {
		t.Fatal("single-leaf proof accepted against wrong root")
	}
}

// TestHashPairSorted confirms sibling order does not change the parent hash.
func TestHashPairSorted(t *testing.T) {
	a, b := mkLeaf(0x01), mkLeaf(0x02)
	if hashPair(a, b) != hashPair(b, a) {
		t.Fatal("hashPair is not order-independent")
	}
}

// TestHashPairKnownVector pins the fold to an independently computed keccak256
// vector, guarding against an accidental swap to SHA3-256 (which shares Go's
// sha3 package but uses different padding). The expected values were produced by
// a separate keccak256 implementation over the same sorted-pair rule.
func TestHashPairKnownVector(t *testing.T) {
	a, b, c, d := mkLeaf(0x0a), mkLeaf(0x0b), mkLeaf(0x0c), mkLeaf(0x0d)

	const wantAB = "0d0f9871649057367c9802ed72c3863f53b2d28ae3d10ece2d4ef0d2f9213784"
	if got := hashPair(a, b); hex.EncodeToString(got[:]) != wantAB {
		t.Fatalf("hashPair keccak mismatch: got %x want %s", got, wantAB)
	}

	const wantRoot = "94d1872730575cc36cfe8dc134c661933532c76cacf4512666feeb402206ca29"
	root := hashPair(hashPair(a, b), hashPair(c, d))
	if hex.EncodeToString(root[:]) != wantRoot {
		t.Fatalf("root keccak mismatch: got %x want %s", root, wantRoot)
	}

	// The public proof path must reach the same verdict as the raw fold.
	if !verifyMerkleProof(a, [][32]byte{b, hashPair(c, d)}, root) {
		t.Fatal("verifyMerkleProof rejected a proof that folds to the known root")
	}
}

// TestAnInnerNodeAlsoFoldsToTheRoot is the reason every caller must compute the
// leaf itself, and it is a property of the tree rather than a bug to fix.
//
// Sibling pairs are hashed and leaves are not, so a leaf and an inner node are
// both just 32 bytes and the fold cannot tell them apart. An inner node,
// presented with the rest of its path, therefore reproduces the anchored root —
// one step shorter, and just as valid to the arithmetic.
//
// A verifier that takes `Leaf` on trust can be handed an inner node and told it
// is the hash of some credential. Verification says true, and it is true: that
// value is in the tree. It says nothing about the credential. The only thing that
// ties the answer to a document is the verifier hashing that document itself.
func TestAnInnerNodeAlsoFoldsToTheRoot(t *testing.T) {
	t.Parallel()

	a, b, c, d := mkLeaf(0x0a), mkLeaf(0x0b), mkLeaf(0x0c), mkLeaf(0x0d)

	left := hashPair(a, b)
	right := hashPair(c, d)
	root := hashPair(left, right)

	// A real leaf with its full path.
	if got := FoldProof(a, [][32]byte{b, right}); got != root {
		t.Fatalf("a real leaf folded to %x, want the root %x", got, root)
	}

	// The inner node, with what remains of the path, reaches the same root.
	if got := FoldProof(left, [][32]byte{right}); got != root {
		t.Fatalf("an inner node folded to %x, want the root %x", got, root)
	}
}

// verifyMerkleProof reports whether leaf, folded together with its sibling path,
// reproduces root.
//
// It lives here because only the tests fold-and-compare in one step: production
// code asks the chain about the folded root instead, so keeping this in the
// package proper left a second name for FoldProof that nothing called.
func verifyMerkleProof(leaf [32]byte, proof [][32]byte, root [32]byte) bool {
	return FoldProof(leaf, proof) == root
}
