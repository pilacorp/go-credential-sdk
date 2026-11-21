package jwt

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

// signingInputFor builds a valid base64url(header).base64url(payload) string
// whose header carries alg, so jws.Verify can parse the compact token that
// Accept builds from it.
func signingInputFor(t *testing.T, alg string) string {
	t.Helper()
	hdr, _ := json.Marshal(map[string]string{"alg": alg})
	pay, _ := json.Marshal(map[string]bool{"test": true})
	return base64.RawURLEncoding.EncodeToString(hdr) + "." + base64.RawURLEncoding.EncodeToString(pay)
}

// Accept is the one check every JWT signing path goes through. Each accepted
// signature is re-checked with the standard library, not with the code under
// test.
func TestSigningKeyAccept(t *testing.T) {
	p256Input := signingInputFor(t, AlgES256)
	secpInput := signingInputFor(t, AlgES256K)

	p256Digest := sha256.Sum256([]byte(p256Input))
	secpDigest := sha256.Sum256([]byte(secpInput))

	p256Key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
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
	secp65, err := crypto.Sign(secpDigest[:], secp) // r||s||v
	if err != nil {
		t.Fatal(err)
	}

	p256SigningKey := SigningKey{ID: "did:example:x#key-1", Alg: AlgES256, PublicKey: &p256Key.PublicKey}
	secpSigningKey := SigningKey{ID: "did:example:x#key-1", Alg: AlgES256K, PublicKey: &secp.PublicKey}

	cases := []struct {
		name    string
		key     SigningKey
		input   string
		sig     []byte
		wantErr string // empty: accepted
	}{
		{"right key", p256SigningKey, p256Input, rs(p256Key, p256Input), ""},
		{"secp256k1 r||s||v is trimmed", secpSigningKey, secpInput, secp65, ""},
		{"another key", p256SigningKey, p256Input, rs(other, p256Input), "does not verify against verification method"},
		{"right key over other data", p256SigningKey, p256Input, rs(p256Key, p256Input+"x"), "does not verify against verification method"},
		{"32 bytes", p256SigningKey, p256Input, make([]byte, 32), "got 32 bytes"},
		{"63 bytes", p256SigningKey, p256Input, make([]byte, 63), "got 63 bytes"},
		{"72 bytes (DER)", p256SigningKey, p256Input, make([]byte, 72), "got 72 bytes"},
		{"256 bytes (RSA)", p256SigningKey, p256Input, make([]byte, 256), "got 256 bytes"},
		{"parsed token: no key, another key's signature", SigningKey{}, p256Input, rs(other, p256Input), ""},
		{"parsed token: no key, wrong length", SigningKey{}, p256Input, make([]byte, 72), "got 72 bytes"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.key.Accept(tc.input, tc.sig)
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
			digest := p256Digest
			if tc.key.Alg == AlgES256K {
				digest = secpDigest
			}
			if tc.key.PublicKey != nil && !ecdsa.Verify(tc.key.PublicKey, digest[:],
				new(big.Int).SetBytes(raw[:32]), new(big.Int).SetBytes(raw[32:])) {
				t.Fatal("the standard library rejects a signature Accept took")
			}
		})
	}
}
