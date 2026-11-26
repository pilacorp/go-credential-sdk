package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	btcec "github.com/btcsuite/btcd/btcec/v2"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

func TestVerifyKeyPair(t *testing.T) {
	priv, err := ethcrypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	other, err := ethcrypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	// btcec's Curve value is not go-ethereum's; the same key must still match.
	btcPub, err := btcec.ParsePubKey(ethcrypto.CompressPubkey(&priv.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		priv *ecdsa.PrivateKey
		pub  *ecdsa.PublicKey
		want bool
	}{
		"same key":                {priv, &priv.PublicKey, true},
		"same key from btcec":     {priv, btcPub.ToECDSA(), true},
		"other key":               {priv, &other.PublicKey, false},
		"P-256 key with no point": {p256, &ecdsa.PublicKey{Curve: elliptic.P256()}, false},
		// The secp256k1 point read as P-256 is off that curve.
		"P-256 label on a secp256k1 key": {priv, &ecdsa.PublicKey{Curve: elliptic.P256(), X: priv.X, Y: priv.Y}, false}, //nolint:staticcheck // the test builds a mislabelled key
	} {
		t.Run(name, func(t *testing.T) {
			if got := VerifyKeyPair(tc.priv, tc.pub); got != tc.want {
				t.Errorf("VerifyKeyPair = %v, want %v", got, tc.want)
			}
		})
	}
}
