package vp_test

import (
	"encoding/hex"
	"strings"
	"testing"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	vmpkg "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
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

// vp11Doc builds a VC 1.1 presentation — the data model whose context defines
// EcdsaSecp256k1Signature2019. Note it carries no validity period: VC 1.1
// defines none on a presentation.
func vp11Doc(holder string) []byte {
	return []byte(`{
		"@context": ["https://www.w3.org/2018/credentials/v1"],
		"id": "urn:uuid:vp-secp-suite-001",
		"type": ["VerifiablePresentation"],
		"holder": "` + holder + `",
		"verifiableCredential": []
	}`)
}

// TestVPSecp256k1Suite_SignVerify signs a presentation with a secp256k1 holder
// key under the VC 1.1 suite and verifies it.
func TestVPSecp256k1Suite_SignVerify(t *testing.T) {
	const holder = "did:example:vp-secp-suite"
	prov, resolver := suiteSecpSetup(t, holder)

	pres, err := vp.ParseJSONPresentation(vp11Doc(holder))
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

	pres, err := vp.ParseJSONPresentation(vp11Doc(holder))
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
// carry beyond the five properties VC 1.1 names. The data model is extensible,
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
			ctx:     `["https://www.w3.org/2018/credentials/v1"]`,
			wantErr: true,
		},
		{
			name: "defined through @vocab",
			ctx:  `["https://www.w3.org/2018/credentials/v1", {"@vocab": "https://nda.vn/vocab#"}]`,
		},
		{
			name: "mapped explicitly to the W3C IRI",
			ctx: `["https://www.w3.org/2018/credentials/v1", {
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
