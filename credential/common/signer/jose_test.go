package signer_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	"github.com/pilacorp/go-credential-sdk/jose/jws"
)

// A P256Provider, the P-256 signer of this module, signs for module jose
// through jws.DigestSigner: both sign a SHA-256 digest and return 64-byte
// r||s (RFC 7518 §3.4).
func TestP256ProviderSignsForJose(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p, err := signer.NewP256Provider(priv)
	if err != nil {
		t.Fatal(err)
	}
	s, err := jws.DigestSigner(jws.AlgES256, func(_ context.Context, d []byte) ([]byte, error) { return p.Sign(d) })
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"iss":"https://issuer.example"}`)
	token, err := jws.Sign(context.Background(), s, p.Public(), jws.Header{"typ": "JWT"}, payload)
	if err != nil {
		t.Fatal(err)
	}
	_, got, err := jws.Verify(token, &priv.PublicKey, []string{jws.AlgES256})
	if err != nil {
		t.Fatalf("jws.Verify: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload = %s, want %s", got, payload)
	}
}
