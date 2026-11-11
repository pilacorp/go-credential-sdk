// Key material of a verification method: W3C Controlled Identifiers v1.0 (CID)
// §2.2.1 to §2.2.3, and publicKeyHex of the older
// EcdsaSecp256k1VerificationKey2019 type. The key is read from its material,
// which names its curve; type is read only for publicKeyHex, which does not,
// so a JsonWebKey2020 or a mislabelled method still gives the key it holds.

package didresolver

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"math/big"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/pilacorp/go-credential-sdk/jose/jwk"
)

const (
	base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	// The Multikey of a P-256 key: the two-byte header and a compressed point
	// (CID §2.2.2), which takes 48 base-58 characters.
	multikeySize    = 35
	multikeyMaxText = 48
)

// publicKey returns the one key vm holds, or nil. CID §2.2.1 forbids two
// material properties for one key. An empty string counts as absent because
// some documents write every property and leave the unused ones empty.
func publicKey(vm map[string]any) crypto.PublicKey {
	j := vm["publicKeyJwk"]
	mb, _ := vm["publicKeyMultibase"].(string)
	hx, _ := vm["publicKeyHex"].(string)
	switch {
	case j != nil && mb == "" && hx == "":
		return jwkKey(j)
	case j == nil && mb != "" && hx == "":
		return multikey(mb)
	case j == nil && mb == "" && hx != "":
		// The value names no curve, so the type must.
		if vm["type"] == "EcdsaSecp256k1VerificationKey2019" {
			return hexKey(hx)
		}
	}
	return nil
}

func jwkKey(v any) crypto.PublicKey {
	m, _ := v.(map[string]any)
	pub, err := jwk.ToPublicKey(m)
	if err != nil {
		return nil
	}
	return pub
}

// multikey reads a base58-btc Multikey of a P-256 public key. CID §2.2.2 has
// a reader raise an error on any other header, a secret key's included; here
// that skips the method. The length is capped first: decoding is quadratic in
// it, and the value comes from the document.
func multikey(s string) crypto.PublicKey {
	text, ok := strings.CutPrefix(s, "z")
	if !ok || len(text) > multikeyMaxText {
		return nil
	}
	raw := decodeBase58(text, multikeySize)
	if raw == nil || raw[0] != 0x80 || raw[1] != 0x24 {
		return nil
	}
	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), raw[2:])
	if x == nil {
		return nil
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
}

// decodeBase58 returns the size bytes s encodes, or nil. It keeps no leading
// zeros of its own: the only caller's value starts with a non-zero header.
func decodeBase58(s string, size int) []byte {
	n, digit, base := new(big.Int), new(big.Int), big.NewInt(int64(len(base58Alphabet)))
	for i := 0; i < len(s); i++ {
		d := strings.IndexByte(base58Alphabet, s[i])
		if d < 0 {
			return nil
		}
		n.Mul(n, base).Add(n, digit.SetInt64(int64(d)))
	}
	if n.BitLen() > size*8 {
		return nil
	}
	return n.FillBytes(make([]byte, size))
}

// hexKey reads a secp256k1 public key from SEC 1 hex, compressed or
// uncompressed, with or without a 0x prefix. ParsePubKey checks the point.
func hexKey(s string) crypto.PublicKey {
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil || !(len(b) == secp256k1.PubKeyBytesLenCompressed || len(b) == secp256k1.PubKeyBytesLenUncompressed && b[0] == 4) {
		return nil
	}
	pub, err := secp256k1.ParsePubKey(b)
	if err != nil {
		return nil
	}
	return pub.ToECDSA()
}
