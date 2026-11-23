package eckey

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"math/big"
	"testing"

	btcec "github.com/btcsuite/btcd/btcec/v2"
	"github.com/ethereum/go-ethereum/crypto"
)

// The generator of each curve, as SEC 1 uncompressed bytes (SEC 2 §2.4.1,
// FIPS 186-5 / SP 800-186 §3.2.1.3), is the private key 1's public key.
const (
	secp256k1G = "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" +
		"483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
	p256G = "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296" +
		"4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
)

func one() []byte {
	b := make([]byte, 32)
	b[31] = 1
	return b
}

func TestUncompressedBytes(t *testing.T) {
	p256, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), one())
	if err != nil {
		t.Fatal(err)
	}
	geth, err := crypto.ToECDSA(one())
	if err != nil {
		t.Fatal(err)
	}
	// btcec's Curve value is not go-ethereum's, and both must read the same.
	_, btcPub := btcec.PrivKeyFromBytes(one())
	btc := btcPub.ToECDSA()

	for name, tc := range map[string]struct {
		pub  *ecdsa.PublicKey
		want string
	}{
		"P-256":             {&p256.PublicKey, p256G},
		"secp256k1 (geth)":  {&geth.PublicKey, secp256k1G},
		"secp256k1 (btcec)": {btc, secp256k1G},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := UncompressedBytes(tc.pub)
			if err != nil {
				t.Fatalf("UncompressedBytes: %v", err)
			}
			if want, _ := hex.DecodeString(tc.want); !bytes.Equal(got, want) {
				t.Errorf("got %x, want %s", got, tc.want)
			}
		})
	}
}

// A P-256 point read as secp256k1 is not on that curve.
func TestUncompressedBytesRefusesPointOffCurve(t *testing.T) {
	p256, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), one())
	if err != nil {
		t.Fatal(err)
	}
	wrong := p256.PublicKey
	wrong.Curve = crypto.S256()
	if _, err := UncompressedBytes(&wrong); err == nil {
		t.Fatal("UncompressedBytes accepted a P-256 point labelled secp256k1")
	}
	if _, err := UncompressedBytes(nil); err == nil {
		t.Fatal("UncompressedBytes accepted a nil key")
	}
}

// A key built by hand without a coordinate is refused, not dereferenced.
func TestUncompressedBytesRefusesMissingCoordinate(t *testing.T) {
	for name, curve := range map[string]elliptic.Curve{"P-256": elliptic.P256(), "secp256k1": crypto.S256()} {
		t.Run(name, func(t *testing.T) {
			if _, err := UncompressedBytes(&ecdsa.PublicKey{Curve: curve}); err == nil {
				t.Fatal("UncompressedBytes accepted a key with no coordinates")
			}
		})
	}
}

// A secp256k1 coordinate outside [0, 2^256) names no point, even when its
// low 256 bits or its absolute value do.
func TestUncompressedBytesRefusesSecp256k1CoordinateOutOfRange(t *testing.T) {
	key, err := crypto.ToECDSA(one())
	if err != nil {
		t.Fatal(err)
	}
	for name, x := range map[string]*big.Int{
		"plus 2^256": new(big.Int).Add(key.X, new(big.Int).Lsh(big.NewInt(1), 256)), //nolint:staticcheck // the test builds a bad coordinate
		"negative":   new(big.Int).Neg(key.X),                                       //nolint:staticcheck // the test builds a bad coordinate
	} {
		t.Run(name, func(t *testing.T) {
			bad := &ecdsa.PublicKey{Curve: crypto.S256(), X: x, Y: key.Y} //nolint:staticcheck // the test builds a bad coordinate
			if _, err := UncompressedBytes(bad); err == nil {
				t.Fatal("UncompressedBytes accepted a coordinate out of range")
			}
		})
	}
}

// The P-256 order n (FIPS 186-5 / SP 800-186 §3.2.1.3).
const p256N = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"

func TestParseP256PrivateKey(t *testing.T) {
	n, _ := new(big.Int).SetString(p256N, 16)
	scalar := func(v *big.Int) []byte { return v.FillBytes(make([]byte, 32)) }
	const outOfRange = "a P-256 private key must be from 1 to n-1"
	for name, tc := range map[string]struct {
		d       []byte
		wantErr string // empty when the key is accepted
	}{
		"1":        {one(), ""},
		"n-1":      {scalar(new(big.Int).Sub(n, big.NewInt(1))), ""},
		"0":        {make([]byte, 32), outOfRange},
		"n":        {scalar(n), outOfRange},
		"31 bytes": {one()[1:], "a P-256 private key is 32 bytes, got 31"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseP256PrivateKey(tc.d)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("err = %v, want nil", err)
			case tc.wantErr != "" && (err == nil || err.Error() != tc.wantErr):
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestParseUncompressedRefusesOtherCurve(t *testing.T) {
	g, err := hex.DecodeString(secp256k1G)
	if err != nil {
		t.Fatal(err)
	}
	// btcec's secp256k1 is not go-ethereum's Curve value, so it is not a
	// curve this package reads; a point on it must not come back as a key.
	if _, err := ParseUncompressed(btcec.S256(), g); err == nil {
		t.Fatal("ParseUncompressed accepted a curve that is neither NIST nor go-ethereum's secp256k1")
	}
}
