package vp_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	vmpkg "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
	"github.com/pilacorp/go-credential-sdk/credential/vp"
)

// A fixed secp256k1 scalar keeps these tests deterministic.
const suiteHolderSecp = "57600b3f2b7e1054094e14cd85c72a40dc74c4ee062bb381cea604b55ce56aec"

func suitePubHex(t *testing.T, privHex string) string {
	t.Helper()
	priv, err := ethcrypto.HexToECDSA(privHex)
	if err != nil {
		t.Fatalf("priv: %v", err)
	}
	return hex.EncodeToString(ethcrypto.FromECDSAPub(&priv.PublicKey))
}

func suiteSecpSetup(t *testing.T, holder string) (signer.SignerProvider, vmpkg.ResolverProvider) {
	t.Helper()
	prov, err := signer.NewDefaultProvider(suiteHolderSecp)
	if err != nil {
		t.Fatalf("secp provider: %v", err)
	}
	resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(holder,
		vmpkg.NewSecp256k1VM(holder, "key-1", suitePubHex(t, suiteHolderSecp))))
	return prov, resolver
}

// vpSuiteDoc builds the VC 2.0 presentation these tests sign. It carries no
// validity period: neither base context defines one on a presentation.
func vpSuiteDoc(holder string) []byte {
	return []byte(`{
		"@context": ["https://www.w3.org/ns/credentials/v2"],
		"id": "urn:uuid:vp-secp-suite-001",
		"type": ["VerifiablePresentation"],
		"holder": "` + holder + `",
		"verifiableCredential": []
	}`)
}

// TestVPSecp256k1Suite_SignVerify signs a presentation with a secp256k1 holder
// key under the suite and verifies it.
func TestVPSecp256k1Suite_SignVerify(t *testing.T) {
	const holder = "did:example:vp-secp-suite"
	prov, resolver := suiteSecpSetup(t, holder)

	pres, err := vp.ParseJSONPresentation(vpSuiteDoc(holder))
	if err != nil {
		t.Fatalf("parse vp: %v", err)
	}
	if err := pres.AddProofByProvider(prov,
		vp.WithVerificationMethodKey("key-1"),
		vp.WithResolver(resolver)); err != nil {
		t.Fatalf("sign vp: %v", err)
	}

	if got := pres.ExtractField("proof.type"); got != "EcdsaSecp256k1Signature2019" {
		t.Errorf("proof.type = %v, want EcdsaSecp256k1Signature2019", got)
	}
	if got, _ := pres.ExtractField("proof.jws").(string); got == "" {
		t.Errorf("proof.jws is empty: %v", pres.ExtractField("proof"))
	}

	if err := pres.Verify(vp.WithResolver(resolver)); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

// TestVPSecp256k1Suite_ChallengeDomain checks the replay and phishing bindings
// survive the new suite: challenge and domain are part of the signed proof
// configuration, so a mismatched expectation must fail.
func TestVPSecp256k1Suite_ChallengeDomain(t *testing.T) {
	const holder = "did:example:vp-secp-suite-cd"
	prov, resolver := suiteSecpSetup(t, holder)

	pres, err := vp.ParseJSONPresentation(vpSuiteDoc(holder))
	if err != nil {
		t.Fatalf("parse vp: %v", err)
	}
	if err := pres.AddProofByProvider(prov,
		vp.WithVerificationMethodKey("key-1"),
		vp.WithResolver(resolver),
		vp.WithChallenge("nonce-secp-1"),
		vp.WithDomain("verifier.example")); err != nil {
		t.Fatalf("sign vp: %v", err)
	}

	if got := pres.ExtractField("proof.challenge"); got != "nonce-secp-1" {
		t.Fatalf("proof.challenge = %v", got)
	}

	cases := []struct {
		name    string
		opts    []vp.PresentationOpt
		wantErr string
	}{
		{"matching", []vp.PresentationOpt{vp.WithExpectedChallenge("nonce-secp-1"), vp.WithExpectedDomain("verifier.example")}, ""},
		{"wrong challenge", []vp.PresentationOpt{vp.WithExpectedChallenge("nonce-999")}, "challenge"},
		{"wrong domain", []vp.PresentationOpt{vp.WithExpectedDomain("attacker.example")}, "domain"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := pres.Verify(append([]vp.PresentationOpt{vp.WithResolver(resolver)}, tc.opts...)...)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("verify: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("verify err = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

// TestVPSecp256k1Suite_ValidityPeriodIsExtensible pins what a presentation may
// carry beyond the properties the base context names. The data model is
// extensible,
// so a validity period is allowed — but only once @context defines the term.
// Without a definition signing must fail rather than silently drop the field,
// which would leave it sitting in a signed document that does not cover it.
func TestVPSecp256k1Suite_ValidityPeriodIsExtensible(t *testing.T) {
	const holder = "did:example:vp-secp-extensible"
	prov, resolver := suiteSecpSetup(t, holder)

	cases := []struct {
		name    string
		ctx     string
		wantErr bool
	}{
		{
			name:    "term left undefined",
			ctx:     `["https://www.w3.org/ns/credentials/v2"]`,
			wantErr: true,
		},
		{
			name: "defined through @vocab",
			ctx:  `["https://www.w3.org/ns/credentials/v2", {"@vocab": "https://nda.vn/vocab#"}]`,
		},
		{
			name: "mapped explicitly to the W3C IRI",
			ctx: `["https://www.w3.org/ns/credentials/v2", {
			        "validUntil": {"@id": "https://www.w3.org/2018/credentials#expirationDate",
			                       "@type": "http://www.w3.org/2001/XMLSchema#dateTime"}}]`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := []byte(`{"@context": ` + tc.ctx + `,
			  "id": "urn:uuid:vp-extensible-001",
			  "type": ["VerifiablePresentation"],
			  "holder": "` + holder + `",
			  "verifiableCredential": [],
			  "validUntil": "2027-09-21T00:00:00Z"}`)

			pres, err := vp.ParseJSONPresentation(doc)
			if err != nil {
				t.Fatalf("parse vp: %v", err)
			}
			err = pres.AddProofByProvider(prov,
				vp.WithVerificationMethodKey("key-1"),
				vp.WithResolver(resolver))

			if tc.wantErr {
				if err == nil {
					t.Fatal("signed with an undefined validUntil; the field would sit in the document uncovered by the signature")
				}
				return
			}
			if err != nil {
				t.Fatalf("sign vp: %v", err)
			}
			if err := pres.Verify(vp.WithResolver(resolver)); err != nil {
				t.Fatalf("verify: %v", err)
			}
			if got := pres.ExtractField("validUntil"); got != "2027-09-21T00:00:00Z" {
				t.Errorf("validUntil = %v, want it preserved", got)
			}
		})
	}
}

// A VC 2.0 presentation signed with a secp256k1 holder key. credentials/v2
// does not define the suite, so the SDK adds its context; the challenge and
// domain the verifier issued stay inside the signature.
func TestVPSecp256k1Suite_SignsVC2Presentation(t *testing.T) {
	const holder = "did:example:vp-secp-suite-vc2"
	prov, resolver := suiteSecpSetup(t, holder)

	raw := []byte(`{
		"@context": ["https://www.w3.org/ns/credentials/v2"],
		"id": "urn:uuid:vp-secp-suite-vc2-001",
		"type": ["VerifiablePresentation"],
		"holder": "` + holder + `",
		"verifiableCredential": []
	}`)

	pres, err := vp.ParseJSONPresentation(raw)
	if err != nil {
		t.Fatalf("parse presentation: %v", err)
	}
	if err := pres.AddProofByProvider(prov,
		vp.WithResolver(resolver), vp.WithVerificationMethodKey("key-1"),
		vp.WithChallenge("nonce-vc2"), vp.WithDomain("https://verifier.example")); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := pres.Verify(vp.WithResolver(resolver),
		vp.WithExpectedChallenge("nonce-vc2"),
		vp.WithExpectedDomain("https://verifier.example")); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := pres.Verify(vp.WithResolver(resolver), vp.WithExpectedChallenge("other")); err == nil {
		t.Fatal("verify accepted a challenge the holder never signed")
	}

	contents, err := pres.GetContents()
	if err != nil {
		t.Fatalf("contents: %v", err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(contents, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	proof, ok := doc["proof"].(map[string]interface{})
	if !ok {
		t.Fatalf("proof is %T, want one object", doc["proof"])
	}
	if proof["type"] != "EcdsaSecp256k1Signature2019" {
		t.Fatalf("proof type = %v", proof["type"])
	}
	if _, ok := proof["jws"].(string); !ok {
		t.Fatalf("proof carries no jws: %v", proof)
	}
	ctx, _ := doc["@context"].([]interface{})
	if len(ctx) == 0 || ctx[0] != "https://www.w3.org/ns/credentials/v2" {
		t.Fatalf("the base context must stay first: %v", doc["@context"])
	}
}

// The real shape of a presentation: it carries a credential. The embedded
// credential keeps its own @context, so adding the suite context to the
// presentation must not disturb it, and both signatures must hold.
func TestVPSecp256k1Suite_CarriesACredential(t *testing.T) {
	const holder = "did:example:vp-secp-with-vc"
	prov, holderResolver := suiteSecpSetup(t, holder)

	const issuer = "did:example:vc-issuer-p256"
	p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("p256 key: %v", err)
	}
	issuerVM, err := vmpkg.NewP256VM(issuer, "key-1", &p256Key.PublicKey)
	if err != nil {
		t.Fatalf("issuer vm: %v", err)
	}
	p256Signer, err := signer.NewP256Provider(p256Key)
	if err != nil {
		t.Fatalf("p256 signer: %v", err)
	}
	issuerResolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(issuer, issuerVM))

	cred, err := vc.NewJSONCredential(vc.CredentialContents{
		Context:   []interface{}{"https://www.w3.org/ns/credentials/v2"},
		ID:        "urn:uuid:vp-embedded-vc",
		Types:     []string{"VerifiableCredential"},
		Issuer:    issuer,
		ValidFrom: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Subject:   []vc.Subject{{ID: "did:example:subject"}},
	})
	if err != nil {
		t.Fatalf("new credential: %v", err)
	}
	if err := cred.AddProofByProvider(p256Signer,
		vc.WithResolver(issuerResolver), vc.WithVerificationMethodKey("key-1")); err != nil {
		t.Fatalf("sign credential: %v", err)
	}
	credJSON, err := cred.GetContents()
	if err != nil {
		t.Fatalf("credential contents: %v", err)
	}
	var credMap map[string]interface{}
	if err := json.Unmarshal(credJSON, &credMap); err != nil {
		t.Fatalf("unmarshal credential: %v", err)
	}

	presDoc := map[string]interface{}{
		"@context":             []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"id":                   "urn:uuid:vp-with-vc-001",
		"type":                 []interface{}{"VerifiablePresentation"},
		"holder":               holder,
		"verifiableCredential": []interface{}{credMap},
	}
	presJSON, err := json.Marshal(presDoc)
	if err != nil {
		t.Fatalf("marshal presentation: %v", err)
	}
	pres, err := vp.ParseJSONPresentation(presJSON)
	if err != nil {
		t.Fatalf("parse presentation: %v", err)
	}
	if err := pres.AddProofByProvider(prov,
		vp.WithResolver(holderResolver), vp.WithVerificationMethodKey("key-1"),
		vp.WithChallenge("nonce-with-vc")); err != nil {
		t.Fatalf("sign presentation: %v", err)
	}
	if err := pres.Verify(vp.WithResolver(holderResolver),
		vp.WithExpectedChallenge("nonce-with-vc")); err != nil {
		t.Fatalf("verify presentation: %v", err)
	}

	// The embedded credential must still verify on its own, untouched.
	out, err := pres.GetContents()
	if err != nil {
		t.Fatalf("presentation contents: %v", err)
	}
	var outMap map[string]interface{}
	if err := json.Unmarshal(out, &outMap); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	embedded, err := json.Marshal(outMap["verifiableCredential"].([]interface{})[0])
	if err != nil {
		t.Fatalf("marshal embedded: %v", err)
	}
	parsedCred, err := vc.ParseJSONCredential(embedded)
	if err != nil {
		t.Fatalf("parse embedded: %v", err)
	}
	if err := parsedCred.Verify(vc.WithResolver(issuerResolver)); err != nil {
		t.Fatalf("the embedded credential stopped verifying: %v", err)
	}
}
