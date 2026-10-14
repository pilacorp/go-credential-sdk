package vp_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	jwtpkg "github.com/pilacorp/go-credential-sdk/credential/common/jwt"
	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	vmpkg "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/vp"
)

// The presentation side of the signer binding, reached through ParsePresentation
// as a consumer reaches it. Three things have to hold, and none of them had a
// test that went through the public entry point:
//
//	the purpose      a presentation is signed for authentication, so a key
//	                 granted only assertionMethod cannot sign one — that is the
//	                 difference between an issuing key and a login key.
//	holder, not iss  the holder names the signer; reading issuer instead would
//	                 let "issuer": attacker stand in for a holder.
//	resolve by body  the document comes from the holder the body names, not from
//	                 the DID prefix of kid.
func TestVP_HolderForgeryThroughTheSignerBinding(t *testing.T) {
	const (
		holderDID   = "did:example:vp-binding-holder"
		attackerDID = "did:example:vp-binding-attacker"
	)

	holderKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen holder key: %v", err)
	}
	attackerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen attacker key: %v", err)
	}
	holderVM := mustP256VM(t, holderDID, "key-1", &holderKey.PublicKey)
	attackerVM := mustP256VM(t, attackerDID, "key-1", &attackerKey.PublicKey)

	// Built by hand: NewDIDDocument grants every key both purposes, which is
	// exactly the case that cannot show the difference. Here key-1 may issue and
	// may not authenticate — an issuing key, not a login key.
	issuingOnly := &vmpkg.DIDDocument{
		ID:                 holderDID,
		VerificationMethod: []vmpkg.VerificationMethodEntry{holderVM},
		AssertionMethod:    []string{holderVM.ID},
		Authentication:     nil,
	}
	bothPurposes := vmpkg.NewDIDDocument(holderDID, holderVM)
	attackerDoc := vmpkg.NewDIDDocument(attackerDID, attackerVM)

	sign := func(t *testing.T, key *ecdsa.PrivateKey, kid string, payload map[string]interface{}) string {
		t.Helper()
		prov, err := signer.NewP256Provider(key)
		if err != nil {
			t.Fatalf("provider: %v", err)
		}
		header, err := json.Marshal(map[string]interface{}{"typ": "vp+jwt", "alg": "ES256", "kid": kid})
		if err != nil {
			t.Fatalf("marshal header: %v", err)
		}
		body, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		input := base64.RawURLEncoding.EncodeToString(header) + "." +
			base64.RawURLEncoding.EncodeToString(body)
		sig, err := jwtpkg.NewJWTSigner(prov).SignString(input)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}

		return input + "." + sig
	}

	for _, tc := range []struct {
		name    string
		doc     *vmpkg.DIDDocument
		key     *ecdsa.PrivateKey
		kid     string
		claims  map[string]interface{}
		wantErr string
	}{
		{
			// An issuing key signing a presentation. The whole point of the two
			// relationship arrays.
			name: "a key granted only assertionMethod signs a presentation",
			doc:  issuingOnly, key: holderKey, kid: holderVM.ID,
			claims:  map[string]interface{}{"holder": holderDID},
			wantErr: "is not granted purpose 'authentication'",
		},
		{
			// issuer must not stand in for holder on a presentation: its signer
			// is its holder, and nothing else.
			name: "issuer names the attacker, no holder at all",
			doc:  bothPurposes, key: attackerKey, kid: attackerVM.ID,
			claims:  map[string]interface{}{"issuer": attackerDID},
			wantErr: "holder",
		},
		{
			// The document resolved is the holder's, and the attacker's kid is
			// not in it.
			name: "holder names the victim, kid points at the attacker",
			doc:  bothPurposes, key: attackerKey, kid: attackerVM.ID,
			claims:  map[string]interface{}{"holder": holderDID},
			wantErr: "verification method",
		},
		{
			name: "the honest shape",
			doc:  bothPurposes, key: holderKey, kid: holderVM.ID,
			claims: map[string]interface{}{"holder": holderDID},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolver := vmpkg.NewStaticResolver(tc.doc, attackerDoc)

			payload := map[string]interface{}{
				"@context": []interface{}{"https://www.w3.org/ns/credentials/v2"},
				"type":     []interface{}{"VerifiablePresentation"},
			}
			for k, v := range tc.claims {
				payload[k] = v
			}

			pres, err := vp.ParsePresentation([]byte(sign(t, tc.key, tc.kid, payload)),
				vp.WithResolver(resolver))
			if err != nil {
				t.Fatalf("refused at parse, so the signer binding was never reached: %v", err)
			}

			err = pres.Verify(vp.WithResolver(resolver))
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("an honest presentation was refused: %v", err)
				}

				return
			}
			if err == nil {
				t.Fatal("a presentation that names no legitimate signer verified")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want one mentioning %q", err, tc.wantErr)
			}
		})
	}
}
