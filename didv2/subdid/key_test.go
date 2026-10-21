package subdid

import (
	"fmt"
	"strings"
	"testing"
)

func TestDeriveSubDIDKey_KDFRows(t *testing.T) {
	r1 := strings.Repeat("11", 32)
	r2 := "00" + strings.Repeat("22", 31)
	r3 := "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140"
	s3 := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-"

	rows := []struct{ root, subID, private, publicKeyHex string }{
		{r1, subIDS1, "46c9a6cf35b07f7d3f5d37f75bf671cc1251d9399a2db28e35b0942765cde8e8", "0x03354b9ae48c3cecaf6636ba88e321847edbf450a2777a012240d6d51705de73d7"},
		{r1, "NV-00123", "cc551f4bc663cdd80c77d51c0d9ebbce538ed47fc4bb2adbf0aee5fa48efd718", "0x03eea1acf8f417b7825a00be2bf446ef87da146f58e664f36f85f91e74d4f79dc1"},
		{r1, s3, "e4381e2c048fa7287f69635b387d3685de6984643139611242b97fea621c7a48", "0x02840520aa2a2dc89c1df1bc0a46d061c50303092f6b0c0af9f1f9bb0effaa537a"},
		{r2, subIDS1, "a838b3223ac0035672f71a2c92be22e8359f111ee9c980234b22dc01d9d4b125", "0x0217f00b15ac4464640c524b43c672d9b90df8bd5081d1d3c1e9ad54a7b959d941"},
		{r2, "NV-00123", "cff7399fbdb7394847bea29b6d5dba7b9f0bf3a51aaa67ab9471a27790651fd7", "0x0211d8a137a79b618a8a386872dfb23b2dd6a05a05c88f67b4c3acbe5f8c423984"},
		{r2, s3, "4097c2eb49e159f35bb98358baf1d8bf444340a94e3bee6f3c8b7df1320797f5", "0x02d15aad4f5842fa3294ab77d843550a00846b349fe81bf773c4deb84a926bd8c6"},
		{r3, subIDS1, "a96dc015717e06f1c69af16fc8989b60f398fa287ab784550581de167a458974", "0x02a480005b1046011aed89aaac3d3abf1da4a1262477b6cec1bad9c5d26a96fb32"},
		{r3, "NV-00123", "c3958f337fa6c69e53bc0372c252ff0df3116fee6178c074cb077fcaf607971a", "0x031a0971e17b99787b28e2072385a25cd8b1e9b299836db9814243ea169346c648"},
		{r3, s3, "617013deeb2bc1ac10fa4c043c646c81919e16f624ce8fadcdda71771d02057e", "0x0274b7a2505ee29545559d1ac097d840b4fedf253ed2a84702bc25733d5fe2ee13"},
	}
	for i, row := range rows {
		key, err := DeriveSubDIDKey(row.root, row.subID)
		if err != nil {
			t.Fatalf("row %d: %v", i+1, err)
		}
		if got := key.GetPrivateKeyHex(); got != "0x"+row.private {
			t.Errorf("row %d: private key = %s, want %s", i+1, got, row.private)
		}
		if got := key.GetPublicKeyHex(); got != row.publicKeyHex {
			t.Errorf("row %d: publicKeyHex = %s, want %s", i+1, got, row.publicKeyHex)
		}
	}

	key, err := DeriveSubDIDKey(r1, subIDS1)
	if err != nil {
		t.Fatal(err)
	}
	p256 := fmt.Sprintf("%064x%064x", key.P256PublicKey.X, key.P256PublicKey.Y)
	if want := "1073cf0910ef789f09d6e2aba3c17fa51465b3b65730dd733dcb1f9a090bd8f72232ca28606fda872acc3dc833ab910cf94956654bac5c8c31dd5f3ff88099a9"; p256 != want {
		t.Errorf("row 1 P-256 public key = %s, want %s", p256, want)
	}

	if _, err := DeriveSubDIDKey(strings.Repeat("22", 31), subIDS1); err == nil {
		t.Error("a 31-byte root (R2 without its leading zero) was accepted")
	}
}
