package jwk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func newP256Key(t *testing.T) *ecdsa.PublicKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &priv.PublicKey
}

func newSecpKey(t *testing.T) *ecdsa.PublicKey {
	t.Helper()
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return priv.PubKey().ToECDSA()
}

func wantErr(t *testing.T, err, target error) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("got error %v, want %v", err, target)
	}
}
