package jwt

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

// Accept is the one check every JWT signing path goes through. Each accepted
// signature is re-checked with the standard library, not with the code under
// test.
func TestSigningKeyAccept(t *testing.T) {
	const input = "header.payload"
	digest := sha256.Sum256([]byte(input))

	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	secp, _ := crypto.GenerateKey()

	rs := func(k *ecdsa.PrivateKey, data string) []byte {
		d := sha256.Sum256([]byte(data))
		r, s, err := ecdsa.Sign(rand.Reader, k, d[:])
		if err != nil {
			t.Fatal(err)
		}
		out := make([]byte, 64)
		r.FillBytes(out[:32])
		s.FillBytes(out[32:])
		return out
	}
	secp65, err := crypto.Sign(digest[:], secp) // r||s||v
	if err != nil {
		t.Fatal(err)
	}

	keyOf := func(k *ecdsa.PrivateKey) SigningKey {
		return SigningKey{ID: "did:example:x#key-1", Alg: AlgES256, PublicKey: &k.PublicKey}
	}
	cases := []struct {
		name    string
		key     SigningKey
		sig     []byte
		wantErr string // empty: accepted
	}{
		{"right key", keyOf(p256), rs(p256, input), ""},
		{"secp256k1 r||s||v is trimmed", keyOf(secp), secp65, ""},
		{"another key", keyOf(p256), rs(other, input), "does not verify against verification method"},
		{"right key over other data", keyOf(p256), rs(p256, input+"x"), "does not verify against verification method"},
		{"32 bytes", keyOf(p256), make([]byte, 32), "got 32 bytes"},
		{"63 bytes", keyOf(p256), make([]byte, 63), "got 63 bytes"},
		{"72 bytes (DER)", keyOf(p256), make([]byte, 72), "got 72 bytes"},
		{"256 bytes (RSA)", keyOf(p256), make([]byte, 256), "got 256 bytes"},
		{"parsed token: no key, another key's signature", SigningKey{}, rs(other, input), ""},
		{"parsed token: no key, wrong length", SigningKey{}, make([]byte, 72), "got 72 bytes"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.key.Accept(input, tc.sig)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				if strings.HasPrefix(tc.wantErr, "got ") && strings.Contains(err.Error(), "another key") {
					t.Fatalf("a wrong length must not be blamed on the key: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Accept: %v", err)
			}
			raw, err := base64.RawURLEncoding.DecodeString(got)
			if err != nil || len(raw) != 64 || !bytes.Equal(raw, tc.sig[:64]) {
				t.Fatalf("encoded signature = %q, want base64url of the first 64 bytes", got)
			}
			if tc.key.PublicKey != nil && !ecdsa.Verify(tc.key.PublicKey, digest[:],
				new(big.Int).SetBytes(raw[:32]), new(big.Int).SetBytes(raw[32:])) {
				t.Fatal("the standard library rejects a signature Accept took")
			}
		})
	}
}
