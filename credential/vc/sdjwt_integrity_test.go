package vc_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	vmpkg "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
)

// The disclosure list is outside the signature, so the signature says nothing
// about how many disclosures arrived or whether they belong. Without a rule, one
// credential has many byte forms that all verify — and Hash() covers those bytes
// and is used as a Merkle leaf. Measured before the fix: five token forms, all
// Verify=<nil>, four distinct hashes.
//
// Three rules close it, and all three live in sdjwt.Reconstruct so the build side
// gets them by running the same function:
//
//	a disclosure matching no digest  — fabricated, or a key binding JWT
//	the same disclosure twice        — same value, second byte form
//	a key binding JWT                — refused outright until it is verified
func TestJOSECredential_DisclosureListIntegrity(t *testing.T) {
	const did = "did:example:sd-integrity"
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen p256: %v", err)
	}
	resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did, mustP256VM(t, did, "key-1", &priv.PublicKey)))
	prov, err := signer.NewP256Provider(priv)
	if err != nil {
		t.Fatalf("p256 provider: %v", err)
	}

	contents := joseContents(did)
	contents.Subject = []vc.Subject{{ID: "did:example:subject", CustomFields: map[string]interface{}{
		"name": "Alice", "bloodType": "O-",
	}}}
	cred, err := vc.NewJOSECredential(contents,
		vc.WithSDSelectivePaths([]string{"credentialSubject.bloodType"}),
		vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver))
	if err != nil {
		t.Fatalf("new sd-jwt credential: %v", err)
	}
	if err := cred.AddProofByProvider(prov, vc.WithResolver(resolver)); err != nil {
		t.Fatalf("sign: %v", err)
	}
	serialized, err := cred.Serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	token, ok := serialized.(string)
	if !ok {
		t.Fatalf("serialized credential is %T, want string", serialized)
	}
	cut := strings.IndexByte(token, '~')
	if cut < 0 {
		t.Fatal("the fixture is not an SD-JWT")
	}
	base, real := token[:cut], strings.Trim(token[cut:], "~")

	fakeArr, err := json.Marshal([]interface{}{"c2FsdA", "bloodType", "A+"})
	if err != nil {
		t.Fatalf("marshal fake disclosure: %v", err)
	}
	fake := base64.RawURLEncoding.EncodeToString(fakeArr)

	kb := base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"kb+jwt","alg":"ES256"}`)) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(`{"nonce":"n","aud":"a"}`)) + ".c2ln"

	for _, tc := range []struct {
		name    string
		token   string
		wantErr string
	}{
		{name: "the token as issued", token: token},
		{name: "the holder reveals nothing", token: base + "~"},
		{
			name:    "a fabricated disclosure alone",
			token:   base + "~" + fake + "~",
			wantErr: "matches nothing in the payload",
		},
		{
			name:    "a fabricated disclosure beside the real one",
			token:   base + "~" + real + "~" + fake + "~",
			wantErr: "matches nothing in the payload",
		},
		{
			name:    "the real disclosure sent twice",
			token:   base + "~" + real + "~" + real + "~",
			wantErr: "sent more than once",
		},
		{
			name:    "a key binding JWT appended",
			token:   base + "~" + real + "~" + kb,
			wantErr: "key binding JWT",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := vc.ParseCredential([]byte(tc.token), vc.WithResolver(resolver))
			if tc.wantErr != "" {
				if err == nil {
					h, _ := parsed.Hash()
					t.Fatalf("accepted; it would have hashed to %s", h)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want one mentioning %q", err, tc.wantErr)
				}

				return
			}
			if err != nil {
				t.Fatalf("a well-formed token was refused: %v", err)
			}
			if err := parsed.Verify(vc.WithResolver(resolver)); err != nil {
				t.Fatalf("verify: %v", err)
			}
		})
	}
}
