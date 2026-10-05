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

// Reconstruct is also what removes the SD-JWT machinery — the _sd digest arrays
// and the root _sd_alg — so skipping it when no disclosure arrived left those in
// the document the caller reads. The digests then looked like credential
// properties: schema validation saw a field the schema does not know, and a
// consumer walking credentialSubject found an array of base64 hashes next to the
// real claims.
//
// Reaching it took no attacker. Present(nil) is the ordinary "reveal nothing"
// call, and both media types issue the payload the same way.
func TestSDJWT_RevealingNothingStillFoldsOutTheDigests(t *testing.T) {
	const did = "did:example:sd-reveal-nothing"
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen p256: %v", err)
	}
	resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did, mustP256VM(t, did, "key-1", &priv.PublicKey)))
	prov, err := signer.NewP256Provider(priv)
	if err != nil {
		t.Fatalf("p256 provider: %v", err)
	}

	contents := func() vc.CredentialContents {
		c := joseContents(did)
		c.Subject = []vc.Subject{{ID: "did:example:subject", CustomFields: map[string]interface{}{
			"name": "Alice", "bloodType": "O-",
		}}}

		return c
	}

	// The 1.1 path keeps its own context, so it gets its own contents.
	v11Contents := func() vc.CredentialContents {
		c := contents()
		c.Context = []interface{}{"https://www.w3.org/2018/credentials/v1"}

		return c
	}

	for _, tc := range []struct {
		name  string
		build func() (vc.Credential, error)
	}{
		{
			name: "vc+sd-jwt",
			build: func() (vc.Credential, error) {
				c, err := vc.NewJOSECredential(contents(),
					vc.WithSDSelectivePaths([]string{"credentialSubject.bloodType"}),
					vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver))
				if err != nil {
					return nil, err
				}

				return c, c.AddProofByProvider(prov, vc.WithResolver(resolver))
			},
		},
		{
			name: "VC 1.1 SD-JWT",
			build: func() (vc.Credential, error) {
				c, err := vc.NewJWTCredential(v11Contents(),
					vc.WithSDSelectivePaths([]string{"credentialSubject.bloodType"}),
					vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver))
				if err != nil {
					return nil, err
				}

				return c, c.AddProofByProvider(prov, vc.WithResolver(resolver))
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			issued, err := tc.build()
			if err != nil {
				t.Fatalf("issue: %v", err)
			}
			serialized, err := issued.Serialize()
			if err != nil {
				t.Fatalf("serialize: %v", err)
			}
			token, ok := serialized.(string)
			if !ok {
				t.Fatalf("serialized credential is %T, want string", serialized)
			}
			base := token[:strings.IndexByte(token, '~')]

			// The three forms a holder who reveals nothing can send. The middle one
			// is what this SDK's own Present(nil) produced before the fix, and the
			// last is what the spec asks for.
			for _, form := range []struct {
				name  string
				token string
			}{
				{"terminator only", base + "~"},
				{"no terminator at all", base},
			} {
				t.Run(form.name, func(t *testing.T) {
					parsed, err := vc.ParseCredential([]byte(form.token), vc.WithResolver(resolver))
					if err != nil {
						t.Fatalf("parse: %v", err)
					}
					if err := parsed.Verify(vc.WithResolver(resolver)); err != nil {
						t.Fatalf("verify: %v", err)
					}

					var m map[string]interface{}
					raw, err := parsed.GetContents()
					if err != nil {
						t.Fatalf("contents: %v", err)
					}
					if err := json.Unmarshal(raw, &m); err != nil {
						t.Fatalf("unmarshal contents: %v", err)
					}
					if _, has := m["_sd_alg"]; has {
						t.Error("_sd_alg is SD-JWT machinery and must not reach the caller")
					}
					subject, ok := m["credentialSubject"].(map[string]interface{})
					if !ok {
						t.Fatalf("credentialSubject = %T, want an object", m["credentialSubject"])
					}
					if sd, has := subject["_sd"]; has {
						t.Errorf("credentialSubject carries _sd = %v; a digest array is not a claim", sd)
					}
					if _, has := subject["bloodType"]; has {
						t.Error("bloodType was withheld and must not be readable")
					}
					if subject["name"] != "Alice" {
						t.Errorf("credentialSubject = %v, want the fields that were never disclosable", subject)
					}
				})
			}
		})
	}
}

// A holder revealing nothing is still presenting an SD-JWT. Dropping the "~"
// made IsSDJWT say no, which is what skipped reconstruction above — and on the
// presentation side envelopeMediaType reads the token, so the envelope was
// labelled vc+jwt over a token whose own typ header said vc+sd-jwt. An outside
// verifier told vc+jwt parses it as plain JWS.
func TestSDJWT_PresentKeepsTheTokenAnSDJWT(t *testing.T) {
	const did = "did:example:sd-present-shape"
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

	sd, err := vc.NewJOSECredential(contents,
		vc.WithSDSelectivePaths([]string{"credentialSubject.bloodType"}),
		vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver))
	if err != nil {
		t.Fatalf("new sd-jwt credential: %v", err)
	}
	if err := sd.AddProofByProvider(prov, vc.WithResolver(resolver)); err != nil {
		t.Fatalf("sign: %v", err)
	}

	presented, err := sd.Present(nil)
	if err != nil {
		t.Fatalf("present nothing: %v", err)
	}
	serialized, err := presented.Serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	token, ok := serialized.(string)
	if !ok {
		t.Fatalf("serialized credential is %T, want string", serialized)
	}
	if !strings.HasSuffix(token, "~") {
		t.Errorf("token = %q, want the SD-JWT terminator even with nothing revealed", token)
	}
	typ, _ := joseHeader(t, presented)
	if typ != "vc+sd-jwt" {
		t.Errorf("typ = %q; the payload still holds digests, so the media type stands", typ)
	}

	// Nothing disclosable means no subset to choose. Said out loud, because
	// BuildSDJWTPresentation would otherwise hand back the same JWT under a
	// terminator it has not earned — different bytes, different Hash.
	plain, err := vc.NewJOSECredential(contents,
		vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver))
	if err != nil {
		t.Fatalf("new jose credential: %v", err)
	}
	if err := plain.AddProofByProvider(prov, vc.WithResolver(resolver)); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := plain.Present(nil); err == nil {
		t.Error("a credential with nothing disclosable was presented selectively")
	}
}

// Decoy digests pad the _sd array so a verifier cannot count how many claims
// were hidden. They carry no disclosure, so a token built from decoys alone has
// SD-JWT machinery in its payload and nothing after the signature.
//
// That made the two ends disagree once reconstruction was gated on the payload:
// the issuer read len(disclosures), called the token vc+jwt and left the "~"
// off, while the parser read _sd_alg, folded the digests out and put the "~"
// back. One credential, two byte forms, two Hash values — and Hash is used as a
// Merkle leaf. Both ends now ask the payload the same question.
func TestSDJWT_DecoysAloneStillMakeItAnSDJWT(t *testing.T) {
	const did = "did:example:sd-decoys-only"
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
		"name": "Alice",
	}}}

	cred, err := vc.NewJOSECredential(contents,
		vc.WithSDDecoyDigests([]vc.Decoy{{Path: "credentialSubject", Count: 2}}),
		vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver))
	if err != nil {
		t.Fatalf("new decoy-only credential: %v", err)
	}
	if err := cred.AddProofByProvider(prov, vc.WithResolver(resolver)); err != nil {
		t.Fatalf("sign: %v", err)
	}

	if typ, _ := joseHeader(t, cred); typ != "vc+sd-jwt" {
		t.Errorf("typ = %q; the payload carries _sd, so a verifier must run SD-JWT processing", typ)
	}
	serialized, err := cred.Serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	token, ok := serialized.(string)
	if !ok {
		t.Fatalf("serialized credential is %T, want string", serialized)
	}
	if !strings.HasSuffix(token, "~") {
		t.Errorf("token = %.40q..., want the SD-JWT terminator", token)
	}
	issuedHash, err := cred.Hash()
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	back, err := vc.ParseCredential([]byte(token), vc.WithResolver(resolver))
	if err != nil {
		t.Fatalf("reparse: %v", err)
	}
	if err := back.Verify(vc.WithResolver(resolver)); err != nil {
		t.Fatalf("verify: %v", err)
	}
	roundTripped, err := back.Serialize()
	if err != nil {
		t.Fatalf("reserialize: %v", err)
	}
	if roundTripped != serialized {
		t.Error("a round trip changed the token's bytes")
	}
	backHash, err := back.Hash()
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if backHash != issuedHash {
		t.Errorf("Hash drifted across a round trip: %s -> %s", issuedHash, backHash)
	}

	// And the decoys are machinery, not claims: they must not reach the caller.
	var m map[string]interface{}
	raw, err := back.GetContents()
	if err != nil {
		t.Fatalf("contents: %v", err)
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal contents: %v", err)
	}
	if _, has := m["_sd_alg"]; has {
		t.Error("_sd_alg reached the caller")
	}
	subject, ok := m["credentialSubject"].(map[string]interface{})
	if !ok {
		t.Fatalf("credentialSubject = %T, want an object", m["credentialSubject"])
	}
	if sd, has := subject["_sd"]; has {
		t.Errorf("credentialSubject carries decoy digests %v", sd)
	}
	if subject["name"] != "Alice" {
		t.Errorf("credentialSubject = %v, want the real claim intact", subject)
	}

	// The VC 1.1 path pins its typ to "JWT", so only the terminator and the
	// digests are observable there — but it reads the same payload question.
	v11 := contents
	v11.Context = []interface{}{"https://www.w3.org/2018/credentials/v1"}
	legacy, err := vc.NewJWTCredential(v11,
		vc.WithSDDecoyDigests([]vc.Decoy{{Path: "credentialSubject", Count: 2}}),
		vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver))
	if err != nil {
		t.Fatalf("new 1.1 decoy-only credential: %v", err)
	}
	if err := legacy.AddProofByProvider(prov, vc.WithResolver(resolver)); err != nil {
		t.Fatalf("sign 1.1: %v", err)
	}
	legacyToken, err := legacy.Serialize()
	if err != nil {
		t.Fatalf("serialize 1.1: %v", err)
	}
	legacyStr, ok := legacyToken.(string)
	if !ok {
		t.Fatalf("serialized 1.1 credential is %T, want string", legacyToken)
	}
	if !strings.HasSuffix(legacyStr, "~") {
		t.Errorf("1.1 token = %.40q..., want the SD-JWT terminator", legacyStr)
	}
	legacyBack, err := vc.ParseCredential([]byte(legacyStr), vc.WithResolver(resolver))
	if err != nil {
		t.Fatalf("reparse 1.1: %v", err)
	}
	legacyRound, err := legacyBack.Serialize()
	if err != nil {
		t.Fatalf("reserialize 1.1: %v", err)
	}
	if legacyRound != legacyToken {
		t.Error("a round trip changed the 1.1 token's bytes")
	}
	legacySubject, _ := legacyBack.ExtractField("credentialSubject").(map[string]interface{})
	if sd, has := legacySubject["_sd"]; has {
		t.Errorf("1.1 credentialSubject carries decoy digests %v", sd)
	}
}
