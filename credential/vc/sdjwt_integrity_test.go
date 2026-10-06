package vc_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	jwtpkg "github.com/pilacorp/go-credential-sdk/credential/common/jwt"
	"github.com/pilacorp/go-credential-sdk/credential/common/sdjwt"
	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	"github.com/pilacorp/go-credential-sdk/credential/common/util"
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

// signJOSEByHand signs payload under typ, so a test can present a token the
// builders would never produce — an SD-JWT from another implementation, or a
// header that disagrees with the bytes it labels.
func signJOSEByHand(t *testing.T, prov signer.SignerProvider, typ, kid string,
	payload map[string]interface{}) string {
	t.Helper()

	header, err := json.Marshal(map[string]interface{}{"typ": typ, "alg": "ES256", "kid": kid})
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(body)
	sig, err := jwtpkg.NewJWTSigner(prov).SignString(signingInput)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	return signingInput + "." + sig
}

// digestOf is the digest an _sd array carries for a disclosure, under the
// default hash algorithm.
func digestOf(disclosure string) string {
	sum := sha256.Sum256([]byte(disclosure))

	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// rawDisclosure builds the salted array a disclosure base64url-encodes.
func rawDisclosure(t *testing.T, salt, name string, value interface{}) string {
	t.Helper()

	b, err := json.Marshal([]interface{}{salt, name, value})
	if err != nil {
		t.Fatalf("marshal disclosure: %v", err)
	}

	return base64.RawURLEncoding.EncodeToString(b)
}

// _sd_alg says which hash an _sd array used. It does not say the token is an
// SD-JWT: RFC 9901 § 4.1.1 makes it OPTIONAL and defaults it to sha-256, so an
// SD-JWT from another implementation need not carry it. Reading it as the
// marker left such a token looking like a plain JWS — Reconstruct never ran, so
// the digests stayed in credentialSubject as though they were claims, Serialize
// dropped the disclosures and the terminator, and the claim the holder did send
// was gone after one round trip.
//
// What does say how a token was secured is the media type in the header and the
// combined format. Those are what this reads now.
func TestSDJWT_FormatIsReadFromTheMediaTypeNotFromSDAlg(t *testing.T) {
	const did = "did:example:sd-marker"
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen p256: %v", err)
	}
	resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did, mustP256VM(t, did, "key-1", &priv.PublicKey)))
	prov, err := signer.NewP256Provider(priv)
	if err != nil {
		t.Fatalf("p256 provider: %v", err)
	}

	disclosure := rawDisclosure(t, "c2FsdDAxc2FsdDAxc2FsdDAx", "bloodType", "O-")
	payload := func(withSDAlg bool) map[string]interface{} {
		m := map[string]interface{}{
			"@context":  []interface{}{"https://www.w3.org/ns/credentials/v2"},
			"type":      []interface{}{"VerifiableCredential"},
			"issuer":    did,
			"validFrom": "2026-01-01T00:00:00Z",
			"credentialSubject": map[string]interface{}{
				"id": "did:example:subject", "name": "Alice",
				"_sd": []interface{}{digestOf(disclosure)},
			},
		}
		if withSDAlg {
			m["_sd_alg"] = "sha-256"
		}

		return m
	}

	t.Run("an SD-JWT with no _sd_alg is still an SD-JWT", func(t *testing.T) {
		for _, tc := range []struct {
			name    string
			typ     string
			suffix  string
			reveals bool
		}{
			{"disclosure sent", "vc+sd-jwt", "~" + disclosure + "~", true},
			{"nothing revealed", "vc+sd-jwt", "~", false},
			{"terminator missing too", "vc+sd-jwt", "", false},
			{"the application/ form of the media type", "application/vc+sd-jwt", "~" + disclosure + "~", true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				token := signJOSEByHand(t, prov, tc.typ, did+"#key-1", payload(false)) + tc.suffix

				cred, err := vc.ParseCredential([]byte(token), vc.WithResolver(resolver))
				if err != nil {
					t.Fatalf("parse: %v", err)
				}
				if err := cred.Verify(vc.WithResolver(resolver)); err != nil {
					t.Fatalf("verify: %v", err)
				}

				subject, ok := cred.ExtractField("credentialSubject").(map[string]interface{})
				if !ok {
					t.Fatalf("credentialSubject = %T, want an object", cred.ExtractField("credentialSubject"))
				}
				if sd, has := subject["_sd"]; has {
					t.Errorf("credentialSubject carries _sd = %v; a digest array is not a claim", sd)
				}
				if tc.reveals && subject["bloodType"] != "O-" {
					t.Errorf("credentialSubject = %v, want the disclosed claim readable", subject)
				}
				if !tc.reveals {
					if _, has := subject["bloodType"]; has {
						t.Error("bloodType was withheld and must not be readable")
					}
				}

				// The token keeps its shape and its identity across a round trip.
				// Serialize used to drop the disclosures and the terminator, so a
				// holder forwarding what it received handed on less than it got.
				serialized, err := cred.Serialize()
				if err != nil {
					t.Fatalf("serialize: %v", err)
				}
				out, ok := serialized.(string)
				if !ok {
					t.Fatalf("serialized credential is %T, want string", serialized)
				}
				if !strings.HasSuffix(out, "~") {
					t.Errorf("token = %.40q..., want the SD-JWT terminator kept", out)
				}
				hash, err := cred.Hash()
				if err != nil {
					t.Fatalf("hash: %v", err)
				}

				back, err := vc.ParseCredential([]byte(out), vc.WithResolver(resolver))
				if err != nil {
					t.Fatalf("reparse: %v", err)
				}
				again, err := back.Serialize()
				if err != nil {
					t.Fatalf("reserialize: %v", err)
				}
				if again != serialized {
					t.Error("a round trip changed the token's bytes")
				}
				backHash, err := back.Hash()
				if err != nil {
					t.Fatalf("hash: %v", err)
				}
				if backHash != hash {
					t.Errorf("Hash drifted across a round trip: %s -> %s", hash, backHash)
				}
				backSubject, _ := back.ExtractField("credentialSubject").(map[string]interface{})
				if tc.reveals && backSubject["bloodType"] != "O-" {
					t.Errorf("the disclosed claim was lost on a round trip: %v", backSubject)
				}
			})
		}
	})

	// vc+jwt means plain JWS. Another verifier told that parses the token as
	// JWS and chokes on the disclosures after the signature, so accepting one
	// here left the two ends reading the same bytes differently.
	t.Run("vc+jwt must not carry the SD-JWT format", func(t *testing.T) {
		for _, tc := range []struct {
			name     string
			withAlg  bool
			suffix   string
			sdInBody bool
		}{
			{name: "disclosures after the signature", suffix: "~" + disclosure + "~", sdInBody: true},
			{name: "_sd_alg in the payload", withAlg: true, sdInBody: true},
			// A vc+jwt carrying only _sd digests — no terminator, no _sd_alg —
			// is not covered here: neither signal fires, and catching it needs a
			// walk of the payload. That rule belongs to
			// requireDisclosableAtTopLevel, which walks it anyway.
		} {
			t.Run(tc.name, func(t *testing.T) {
				token := signJOSEByHand(t, prov, vc.TypeVCJWT, did+"#key-1", payload(tc.withAlg)) + tc.suffix

				_, err := vc.ParseCredential([]byte(token), vc.WithResolver(resolver))
				if err == nil {
					t.Fatal("a vc+jwt carrying the SD-JWT format was accepted")
				}
				if !strings.Contains(err.Error(), "does not match the SD-JWT format") {
					t.Fatalf("err = %v, want one naming the mismatch", err)
				}
			})
		}
	})

	// A VC 1.1 token types itself "JWT" either way, so there is no media type to
	// read. The combined format is the signal that does not depend on _sd_alg.
	t.Run("VC 1.1 falls back to the combined format", func(t *testing.T) {
		inner := map[string]interface{}{
			"@context":     []interface{}{"https://www.w3.org/2018/credentials/v1"},
			"type":         []interface{}{"VerifiableCredential"},
			"issuer":       did,
			"issuanceDate": "2026-01-01T00:00:00Z",
			"credentialSubject": map[string]interface{}{
				"id": "did:example:subject", "_sd": []interface{}{digestOf(disclosure)},
			},
		}
		for _, tc := range []struct {
			name    string
			suffix  string
			reveals bool
		}{
			{"disclosure sent, no _sd_alg", "~" + disclosure + "~", true},
			{"nothing revealed, no _sd_alg", "~", false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				token := signJOSEByHand(t, prov, "JWT", did+"#key-1",
					map[string]interface{}{"iss": did, "vc": inner}) + tc.suffix

				cred, err := vc.ParseCredential([]byte(token), vc.WithResolver(resolver))
				if err != nil {
					t.Fatalf("parse: %v", err)
				}
				subject, _ := cred.ExtractField("credentialSubject").(map[string]interface{})
				if sd, has := subject["_sd"]; has {
					t.Errorf("credentialSubject carries _sd = %v", sd)
				}
				if tc.reveals && subject["bloodType"] != "O-" {
					t.Errorf("credentialSubject = %v, want the disclosed claim readable", subject)
				}
			})
		}
	})
}

// revokedStatusListServer serves a BitstringStatusList whose bit at revokedAt
// is set, so a credential pointing there really is revoked.
func revokedStatusListServer(t *testing.T, revokedAt int) *httptest.Server {
	t.Helper()

	bits := make([]byte, 16)
	bits[revokedAt/8] |= 1 << (revokedAt % 8)
	encoded, err := util.CompressToBase64URL(bits)
	if err != nil {
		t.Fatalf("compress status list: %v", err)
	}

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"credentialSubject": map[string]interface{}{
					"statusPurpose": "revocation", "encodedList": encoded,
				},
			},
		}); err != nil {
			t.Errorf("encode status list: %v", err)
		}
	}))
}

// Selective disclosure belongs to credentialSubject and nowhere else. Checking
// only the root of the payload for _sd missed the case that matters: _sd nested
// inside a top-level property is still _sd.
//
// An issuer that made every field of credentialStatus disclosable left a holder
// able to withhold all of them. Reconstruction then produced
// credentialStatus: {}, and checkRevocation reads an empty object as "this
// credential does not use revocation" and returns nil — so a revoked credential
// verified clean. The holder gave up nothing to do it: credentialSubject came
// back identical either way, so the credential still presented in full.
//
// Three steps that are each defensible on their own chain into that: the guard
// looked only at the root, Reconstruct deletes _sd once it has applied whatever
// disclosures arrived, and checkRevocation treats {} as absent. The one place
// that can still tell the difference is the guard, before Reconstruct removes
// the evidence — which is where the rule now lives.
func TestSDJWT_SelectiveDisclosureIsConfinedToTheSubject(t *testing.T) {
	const (
		issuerDID = "did:example:sd-confine"
		revokedAt = 7
	)
	srv := revokedStatusListServer(t, revokedAt)
	defer srv.Close()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen p256: %v", err)
	}
	resolver := vmpkg.NewStaticResolver(
		vmpkg.NewDIDDocument(issuerDID, mustP256VM(t, issuerDID, "key-1", &priv.PublicKey)))
	prov, err := signer.NewP256Provider(priv)
	if err != nil {
		t.Fatalf("p256 provider: %v", err)
	}

	statusDisclosures := []string{
		rawDisclosure(t, "c2FsdDAwc2FsdDAwc2FsdDAw", "type", "BitstringStatusListEntry"),
		rawDisclosure(t, "c2FsdDExc2FsdDExc2FsdDEx", "statusListCredential", srv.URL+"/status/1"),
		rawDisclosure(t, "c2FsdDIyc2FsdDIyc2FsdDIy", "statusListIndex", strconv.Itoa(revokedAt)),
		rawDisclosure(t, "c2FsdDMzc2FsdDMzc2FsdDMz", "statusPurpose", "revocation"),
	}
	hiddenStatus := map[string]interface{}{"_sd": []interface{}{}}
	for _, d := range statusDisclosures {
		hiddenStatus["_sd"] = append(hiddenStatus["_sd"].([]interface{}), digestOf(d))
	}

	payload := func(extra map[string]interface{}) map[string]interface{} {
		m := map[string]interface{}{
			"@context":  []interface{}{"https://www.w3.org/ns/credentials/v2"},
			"id":        "urn:uuid:sd-confine",
			"type":      []interface{}{"VerifiableCredential"},
			"issuer":    issuerDID,
			"validFrom": "2026-01-01T00:00:00Z",
			"credentialSubject": map[string]interface{}{
				"id": "did:example:subject", "name": "Alice",
			},
			"_sd_alg": "sha-256",
		}
		for k, v := range extra {
			m[k] = v
		}

		return m
	}
	withheld := rawDisclosure(t, "c2FsdDk5c2FsdDk5c2FsdDk5", "validUntil", "2020-01-01T00:00:00Z")

	// The credential this is all about: revoked, with the whole of
	// credentialStatus disclosable. It is refused whatever the holder sends,
	// because the issuer should never have signed it that way — and refusing
	// only the withholding holder would leave the same token one `~` away from
	// passing.
	t.Run("a revoked credential cannot hide its credentialStatus", func(t *testing.T) {
		base := signJOSEByHand(t, prov, vc.TypeVCSDJWT, issuerDID+"#key-1",
			payload(map[string]interface{}{"credentialStatus": hiddenStatus}))

		for _, tc := range []struct {
			name  string
			token string
		}{
			{"every disclosure sent", base + "~" + strings.Join(statusDisclosures, "~") + "~"},
			{"all four withheld", base + "~"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				cred, err := vc.ParseCredential([]byte(tc.token), vc.WithResolver(resolver))
				if err != nil {
					if !strings.Contains(err.Error(), "not permitted in \"credentialStatus\"") {
						t.Fatalf("err = %v, want one naming credentialStatus", err)
					}

					return
				}
				// Accepted. The only way that is not a bypass is if revocation
				// is still caught.
				verr := cred.Verify(vc.WithResolver(resolver), vc.WithCheckRevocation())
				if verr == nil {
					t.Fatalf("a revoked credential verified clean; credentialStatus = %v",
						cred.ExtractField("credentialStatus"))
				}
				if !strings.Contains(verr.Error(), "revoked") {
					t.Fatalf("err = %v, want the revocation to be reported", verr)
				}
			})
		}
	})

	// The VC 1.1 path is where this actually regressed. It had no call to the
	// guard at all, and it is the path already tagged and in use. Before
	// Reconstruct started running on a zero-disclosure token, credentialStatus
	// kept its _sd array and checkRevocation refused it by accident, for
	// missing statusListCredential; once the digests were cleaned up the object
	// became {} and the refusal turned into a pass.
	t.Run("the VC 1.1 path is held to the same rule", func(t *testing.T) {
		inner := map[string]interface{}{
			"@context":     []interface{}{"https://www.w3.org/2018/credentials/v1"},
			"type":         []interface{}{"VerifiableCredential"},
			"issuer":       issuerDID,
			"issuanceDate": "2026-01-01T00:00:00Z",
			"credentialSubject": map[string]interface{}{
				"id": "did:example:subject", "name": "Alice",
			},
			"_sd_alg":          "sha-256",
			"credentialStatus": hiddenStatus,
		}
		base := signJOSEByHand(t, prov, "JWT", issuerDID+"#key-1",
			map[string]interface{}{"iss": issuerDID, "vc": inner})

		for _, tc := range []struct {
			name  string
			token string
		}{
			{"every disclosure sent", base + "~" + strings.Join(statusDisclosures, "~") + "~"},
			{"all four withheld", base + "~"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				cred, err := vc.ParseCredential([]byte(tc.token), vc.WithResolver(resolver))
				if err != nil {
					if !strings.Contains(err.Error(), "not permitted in \"credentialStatus\"") {
						t.Fatalf("err = %v, want one naming credentialStatus", err)
					}

					return
				}
				verr := cred.Verify(vc.WithResolver(resolver), vc.WithCheckRevocation())
				if verr == nil {
					t.Fatalf("a revoked VC 1.1 credential verified clean; credentialStatus = %v",
						cred.ExtractField("credentialStatus"))
				}
				if !strings.Contains(verr.Error(), "revoked") {
					t.Fatalf("err = %v, want the revocation to be reported", verr)
				}
			})
		}
	})

	// The machinery can sit at any depth and in either shape.
	t.Run("SD machinery outside the subject is refused wherever it sits", func(t *testing.T) {
		for _, tc := range []struct {
			name  string
			extra map[string]interface{}
			wants string
		}{
			{
				name:  "_sd at the root",
				extra: map[string]interface{}{"_sd": []interface{}{digestOf(withheld)}},
				wants: "carries _sd at the root",
			},
			{
				name: "_sd one level inside a property",
				extra: map[string]interface{}{"termsOfUse": map[string]interface{}{
					"type": "TrustFrameworkPolicy", "_sd": []interface{}{digestOf(withheld)}}},
				wants: `not permitted in "termsOfUse"`,
			},
			{
				name: "_sd two levels down",
				extra: map[string]interface{}{"evidence": map[string]interface{}{
					"verification": map[string]interface{}{"_sd": []interface{}{digestOf(withheld)}}}},
				wants: `not permitted in "evidence"`,
			},
			{
				name: "an array element placeholder",
				extra: map[string]interface{}{"termsOfUse": []interface{}{
					map[string]interface{}{"...": digestOf(withheld)}}},
				wants: `not permitted in "termsOfUse"`,
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				token := signJOSEByHand(t, prov, vc.TypeVCSDJWT, issuerDID+"#key-1",
					payload(tc.extra)) + "~"

				_, err := vc.ParseCredential([]byte(token), vc.WithResolver(resolver))
				if err == nil {
					t.Fatal("selective disclosure outside credentialSubject was accepted")
				}
				if !strings.Contains(err.Error(), tc.wants) {
					t.Fatalf("err = %v, want one mentioning %q", err, tc.wants)
				}
			})
		}
	})

	// vc+jwt promises nothing was selectively disclosed, so the subject is not
	// exempt under that media type. This is the shape neither the combined
	// format nor _sd_alg reveals, which is why the walk is told what the header
	// declared.
	t.Run("a vc+jwt is not exempt even inside the subject", func(t *testing.T) {
		token := signJOSEByHand(t, prov, vc.TypeVCJWT, issuerDID+"#key-1",
			map[string]interface{}{
				"@context":  []interface{}{"https://www.w3.org/ns/credentials/v2"},
				"type":      []interface{}{"VerifiableCredential"},
				"issuer":    issuerDID,
				"validFrom": "2026-01-01T00:00:00Z",
				"credentialSubject": map[string]interface{}{
					"id": "did:example:subject", "_sd": []interface{}{digestOf(withheld)}},
			})

		_, err := vc.ParseCredential([]byte(token), vc.WithResolver(resolver))
		if err == nil {
			t.Fatal("a vc+jwt carrying _sd in its subject was accepted")
		}
		if !strings.Contains(err.Error(), `not permitted in "credentialSubject"`) {
			t.Fatalf("err = %v, want the subject named under a vc+jwt", err)
		}
	})

	// And the thing the rule exists to allow still works.
	t.Run("the subject itself stays disclosable", func(t *testing.T) {
		bloodType := rawDisclosure(t, "c2FsZEJCc2FsZEJCc2FsZEJC", "bloodType", "O-")
		token := signJOSEByHand(t, prov, vc.TypeVCSDJWT, issuerDID+"#key-1",
			map[string]interface{}{
				"@context":  []interface{}{"https://www.w3.org/ns/credentials/v2"},
				"type":      []interface{}{"VerifiableCredential"},
				"issuer":    issuerDID,
				"validFrom": "2026-01-01T00:00:00Z",
				"_sd_alg":   "sha-256",
				"credentialSubject": map[string]interface{}{
					"id": "did:example:subject", "name": "Alice",
					"_sd": []interface{}{digestOf(bloodType)}},
			}) + "~" + bloodType + "~"

		cred, err := vc.ParseCredential([]byte(token), vc.WithResolver(resolver))
		if err != nil {
			t.Fatalf("a disclosable subject claim was refused: %v", err)
		}
		if err := cred.Verify(vc.WithResolver(resolver)); err != nil {
			t.Fatalf("verify: %v", err)
		}
		subject, _ := cred.ExtractField("credentialSubject").(map[string]interface{})
		if subject["bloodType"] != "O-" {
			t.Errorf("credentialSubject = %v, want the disclosed claim readable", subject)
		}
	})
}

// WithSDDisclosures is the advanced path the README documents: the caller runs
// BuildDisclosures itself, carries the processed claims — digests and all — into
// the contents, and hands the matching disclosures to the builder.
//
// Refusing it outright broke a credential that signed and verified before. The
// reason given was that a disclosure made elsewhere cannot match a digest this
// payload holds, which is true only when the builder generated the digests from
// WithSDSelectivePaths; when the caller supplies both halves they do match. So
// the builder now validates instead of refusing, and Reconstruct is what
// answers the question, bringing the § 7.1 rules with it.
func TestSDJWT_PrebuiltDisclosuresAreValidatedNotRefused(t *testing.T) {
	const did = "did:example:sd-prebuilt"
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen p256: %v", err)
	}
	resolver := vmpkg.NewStaticResolver(
		vmpkg.NewDIDDocument(did, mustP256VM(t, did, "key-1", &priv.PublicKey)))
	prov, err := signer.NewP256Provider(priv)
	if err != nil {
		t.Fatalf("p256 provider: %v", err)
	}

	// The caller's own first half: digests for one subject claim.
	prebuild := func(t *testing.T) (map[string]interface{}, []string) {
		t.Helper()
		res, err := sdjwt.BuildDisclosures(sdjwt.BuildDisclosuresInput{
			VC: map[string]interface{}{"credentialSubject": map[string]interface{}{
				"id": "did:example:subject", "name": "Alice", "bloodType": "O-",
			}},
			SelectivePaths: []string{"credentialSubject.bloodType"},
		})
		if err != nil {
			t.Fatalf("build disclosures: %v", err)
		}
		processed, ok := res.ProcessedVC["credentialSubject"].(map[string]interface{})
		if !ok {
			t.Fatalf("processed subject is %T, want an object", res.ProcessedVC["credentialSubject"])
		}
		custom := map[string]interface{}{}
		for k, v := range processed {
			if k != "id" {
				custom[k] = v
			}
		}

		return custom, res.Disclosures
	}

	type builder struct {
		name  string
		build func(vc.CredentialContents, ...vc.CredentialOpt) (vc.Credential, error)
		ctx   []interface{}
	}
	builders := []builder{
		{
			name: "vc+sd-jwt",
			ctx:  []interface{}{"https://www.w3.org/ns/credentials/v2"},
			build: func(c vc.CredentialContents, o ...vc.CredentialOpt) (vc.Credential, error) {
				return vc.NewJOSECredential(c, o...)
			},
		},
		{
			name: "VC 1.1 SD-JWT",
			ctx:  []interface{}{"https://www.w3.org/2018/credentials/v1"},
			build: func(c vc.CredentialContents, o ...vc.CredentialOpt) (vc.Credential, error) {
				return vc.NewJWTCredential(c, o...)
			},
		},
	}

	for _, b := range builders {
		t.Run(b.name, func(t *testing.T) {
			contents := func(custom map[string]interface{}) vc.CredentialContents {
				return vc.CredentialContents{
					Context:   b.ctx,
					ID:        "urn:uuid:sd-prebuilt",
					Issuer:    did,
					Types:     []string{"VerifiableCredential"},
					ValidFrom: time.Now().Add(-time.Hour),
					Subject:   []vc.Subject{{ID: "did:example:subject", CustomFields: custom}},
				}
			}

			t.Run("matching disclosures round-trip", func(t *testing.T) {
				custom, disclosures := prebuild(t)

				cred, err := b.build(contents(custom),
					vc.WithSDDisclosures(disclosures),
					vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver))
				if err != nil {
					t.Fatalf("a matching prebuilt disclosure was refused: %v", err)
				}
				signable, ok := cred.(interface {
					AddProofByProvider(signer.SignerProvider, ...vc.CredentialOpt) error
				})
				if !ok {
					t.Fatalf("credential is %T, want one that can be signed", cred)
				}
				if err := signable.AddProofByProvider(prov, vc.WithResolver(resolver)); err != nil {
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
				// _sd_alg has to have been written, or the token comes out as a
				// plain JWT and the disclosures are dropped on the floor.
				if !strings.HasSuffix(token, "~") {
					t.Fatalf("token = %.40q..., want the disclosures and terminator kept", token)
				}

				back, err := vc.ParseCredential([]byte(token), vc.WithResolver(resolver))
				if err != nil {
					t.Fatalf("the SDK refused the token it just built: %v", err)
				}
				if err := back.Verify(vc.WithResolver(resolver)); err != nil {
					t.Fatalf("verify: %v", err)
				}
				subject, _ := back.ExtractField("credentialSubject").(map[string]interface{})
				if subject["bloodType"] != "O-" {
					t.Errorf("credentialSubject = %v, want the prebuilt claim reconstructed", subject)
				}
				if sd, has := subject["_sd"]; has {
					t.Errorf("credentialSubject carries _sd = %v", sd)
				}
			})

			// Validated, not trusted. Each of these is a § 7.1 rule, reached
			// through the builder rather than the parser.
			for _, tc := range []struct {
				name    string
				mangle  func(t *testing.T, custom map[string]interface{}, ds []string) []string
				wantErr string
			}{
				{
					name: "a disclosure matching no digest",
					mangle: func(t *testing.T, _ map[string]interface{}, ds []string) []string {
						return append(ds, rawDisclosure(t, "c2FsdFhYc2FsdFhYc2FsdFhY", "nickname", "Al"))
					},
					wantErr: "matches nothing in the payload",
				},
				{
					name: "the same disclosure twice",
					mangle: func(_ *testing.T, _ map[string]interface{}, ds []string) []string {
						return append(ds, ds[0])
					},
					wantErr: "sent more than once",
				},
				{
					name: "a disclosure for a digest the caller never carried",
					mangle: func(t *testing.T, custom map[string]interface{}, ds []string) []string {
						delete(custom, "_sd")

						return ds
					},
					wantErr: "matches nothing in the payload",
				},
			} {
				t.Run(tc.name, func(t *testing.T) {
					custom, disclosures := prebuild(t)
					disclosures = tc.mangle(t, custom, disclosures)

					_, err := b.build(contents(custom),
						vc.WithSDDisclosures(disclosures),
						vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver))
					if err == nil {
						t.Fatal("an invalid prebuilt disclosure set was accepted")
					}
					if !strings.Contains(err.Error(), "invalid SD-JWT disclosures") {
						t.Fatalf("err = %v, want it reported as invalid disclosures", err)
					}
					if !strings.Contains(err.Error(), tc.wantErr) {
						t.Fatalf("err = %v, want one mentioning %q", err, tc.wantErr)
					}
				})
			}
		})
	}
}
