package jsonmap

import (
	stdcrypto "crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
)

// TestJWS2020_Rejections checks the JsonWebSignature2020 rules a verifier
// enforces: the proof options are signed (CCG CG-FINAL 2022-07-21 §3 with
// Linked Data Proofs), crit names only b64 (RFC 7515 §4.1.11), a public JWK
// carries no d (§3.2.1), RSA keys have 2048 bits or more (§3.1) and PS256 uses
// a 32-byte salt (RFC 7518 §3.5).
func TestJWS2020_Rejections(t *testing.T) {
	const did = "did:example:jws"
	sp, pub := p256Signer(t)
	vm, err := verificationmethod.NewP256VM(did, "key-1", pub)
	if err != nil {
		t.Fatal(err)
	}
	resolver := verificationmethod.NewStaticResolver(verificationmethod.NewDIDDocument(did, vm))

	signed := func(t *testing.T) JSONMap {
		m := testCredential()
		if err := m.AddJWSProof(sp, did+"#key-1", "assertionMethod", WithChallenge("n-1"), WithDomain("rp.example")); err != nil {
			t.Fatal(err)
		}
		return m
	}
	proofOf := func(m JSONMap) map[string]interface{} { return m[proofField].(map[string]interface{}) }

	if ok, err := func() (bool, error) { m := signed(t); return m.VerifyProof(resolver, "") }(); !ok || err != nil {
		t.Fatalf("untouched proof: %v, %v", ok, err)
	}
	for field, value := range map[string]interface{}{"proofPurpose": "authentication", "challenge": "n-2", "domain": "evil.example", "created": "2000-01-01T00:00:00Z"} {
		m := signed(t)
		proofOf(m)[field] = value
		if ok, err := m.VerifyProof(resolver, ""); ok || err == nil || !strings.Contains(err.Error(), "signature verification failed") {
			t.Errorf("%s changed after signing: ok=%v err=%v, want a failed signature", field, ok, err)
		}
	}

	m := signed(t)
	p := proofOf(m)
	parts := strings.SplitN(p["jws"].(string), "..", 2)
	hdr, _ := json.Marshal(map[string]interface{}{"alg": "ES256", "b64": false, "crit": []string{"b64", "urn:x:unknown"}})
	p["jws"] = base64.RawURLEncoding.EncodeToString(hdr) + ".." + parts[1]
	if _, err := m.VerifyProof(resolver, ""); err == nil || !strings.Contains(err.Error(), "crit names") {
		t.Errorf("unknown crit: err = %v", err)
	}

	var withD verificationmethod.VerificationMethodEntry
	raw, _ := json.Marshal(vm)
	raw = []byte(strings.Replace(string(raw), `"kty":"EC"`, `"kty":"EC","d":"cHJpdmF0ZQ"`, 1))
	if err := json.Unmarshal(raw, &withD); err != nil {
		t.Fatal(err)
	}
	m = signed(t)
	if _, err := m.VerifyProof(verificationmethod.NewStaticResolver(verificationmethod.NewDIDDocument(did, withD)), ""); err == nil || !strings.Contains(err.Error(), "private key member d") {
		t.Errorf("JWK with d: err = %v", err)
	}

	rsaCase := func(t *testing.T, bits int, opts *rsa.PSSOptions) error {
		key, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			t.Fatal(err)
		}
		rs, _ := signer.NewRSAFunc(func(d []byte) ([]byte, error) { return rsa.SignPSS(rand.Reader, key, stdcrypto.SHA256, d, opts) }, "PS256")
		m := testCredential()
		if err := m.AddJWSProof(rs, did+"#rsa", "assertionMethod"); err != nil {
			t.Fatal(err)
		}
		res := verificationmethod.NewStaticResolver(verificationmethod.NewDIDDocument(did, verificationmethod.NewRSAVM(did, "rsa", &key.PublicKey)))
		_, err = m.VerifyProof(res, "")
		return err
	}
	if err := rsaCase(t, 2048, &rsa.PSSOptions{SaltLength: sha256.Size}); err != nil {
		t.Fatalf("PS256 with a 32-byte salt: %v", err)
	}
	if err := rsaCase(t, 2048, nil); err == nil {
		t.Error("PS256 with the largest salt verified")
	}
	if err := rsaCase(t, 1024, &rsa.PSSOptions{SaltLength: sha256.Size}); err == nil || !strings.Contains(err.Error(), "at least 2048") {
		t.Errorf("1024-bit RSA: err = %v", err)
	}
}
