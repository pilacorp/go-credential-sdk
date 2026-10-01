package vc_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	jwtpkg "github.com/pilacorp/go-credential-sdk/credential/common/jwt"
	"github.com/pilacorp/go-credential-sdk/credential/common/sdjwt"
	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	vmpkg "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
)

// signSDJWTToken assembles and signs a VC 1.1 SD-JWT by hand, the way a non-SDK
// producer would, and appends the disclosures the holder chose to show. The 1.1
// path is where selective disclosure still lives: vc+jwt refuses it outright
// (see TestJOSECredential_RefusesSelectiveDisclosure), while a 1.1 token keeps
// its claims under vc and hides them through vc._sd.
func signSDJWTToken(t *testing.T, key *ecdsa.PrivateKey, kid string,
	payload map[string]interface{}, shown []string) string {
	t.Helper()

	prov, err := signer.NewP256Provider(key)
	if err != nil {
		t.Fatalf("provider: %v", err)
	}
	header, err := json.Marshal(map[string]interface{}{"typ": "JWT", "alg": "ES256", "kid": kid})
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(body)
	sig, err := jwtpkg.NewJWTSigner(prov).SignString(signingInput)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	token := signingInput + "." + sig
	for _, d := range shown {
		token += "~" + d
	}
	if len(shown) > 0 {
		token += "~"
	}
	return token
}

// Selective disclosure moves a property out of the signature: the digest is
// signed, the value travels beside it, and whoever holds the token decides
// whether to send it. That is the point for a claim nobody checks — and a
// forgery primitive for a claim the verifier decides on.
//
// Two directions, both run end to end through ParseCredential:
//
//	disclosing issuer   — the attacker signs with its own key, names itself in
//	                      iss (which matches, because the signed payload has no
//	                      issuer to compare against) and lets the disclosure put
//	                      the victim's DID in afterwards.
//	withholding one     — the issuer makes validUntil or credentialStatus
//	                      selectively disclosable, and the holder simply does not
//	                      send it; the expiry and revocation checks then run on a
//	                      payload where the property is absent.
func TestVC_SecuredClaimsMustNotBeSelectivelyDisclosed(t *testing.T) {
	const (
		attackerDID = "did:example:sd-attacker"
		victimDID   = "did:example:sd-victim"
	)

	attackerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen attacker key: %v", err)
	}
	victimKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen victim key: %v", err)
	}
	attackerVM := mustP256VM(t, attackerDID, "key-1", &attackerKey.PublicKey)
	victimVM := mustP256VM(t, victimDID, "key-1", &victimKey.PublicKey)
	resolver := vmpkg.NewStaticResolver(
		vmpkg.NewDIDDocument(attackerDID, attackerVM),
		vmpkg.NewDIDDocument(victimDID, victimVM),
	)

	for _, tc := range []struct {
		name  string
		path  string // property made selectively disclosable
		show  bool   // does the holder attach the disclosure?
		byVic bool   // signed by the victim (a real issuer) rather than the attacker
	}{
		{name: "issuer disclosed by an attacker signing with its own key", path: "issuer", show: true},
		{name: "expirationDate withheld by the holder", path: "expirationDate", show: false, byVic: true},
		{name: "credentialStatus withheld by the holder", path: "credentialStatus", show: false, byVic: true},
		{name: "issuanceDate withheld by the holder", path: "issuanceDate", show: false, byVic: true},
		{name: "type disclosed", path: "type", show: true, byVic: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			signer, vm := attackerKey, attackerVM
			iss := attackerDID
			if tc.byVic {
				signer, vm, iss = victimKey, victimVM, victimDID
			}
			// A VC 1.1 credential: the document sits under the vc claim, and
			// vc._sd is what hides a property inside it.
			inner := map[string]interface{}{
				"@context":          []interface{}{"https://www.w3.org/2018/credentials/v1"},
				"type":              []interface{}{"VerifiableCredential"},
				"issuer":            victimDID,
				"issuanceDate":      "2019-01-01T00:00:00Z",
				"expirationDate":    "2020-01-01T00:00:00Z", // long expired
				"credentialStatus":  map[string]interface{}{"type": "BitstringStatusListEntry", "id": "https://example.org/status/1"},
				"credentialSubject": map[string]interface{}{"id": "did:example:subject", "role": "admin"},
			}
			built, err := sdjwt.BuildDisclosures(sdjwt.BuildDisclosuresInput{
				VC: inner, SelectivePaths: []string{tc.path},
			})
			if err != nil {
				t.Fatalf("build disclosures: %v", err)
			}
			shown := built.Disclosures
			if !tc.show {
				shown = nil
			}
			token := signSDJWTToken(t, signer, vm.ID, map[string]interface{}{
				"iss": iss,
				"vc":  built.ProcessedVC,
			}, shown)

			cred, err := vc.ParseCredential([]byte(token), vc.WithResolver(resolver))
			if err != nil {
				// Named when the disclosure was attached, generic when it was
				// withheld — a digest does not record which property it stood
				// for. Either is a refusal; anything else is luck.
				if !strings.Contains(err.Error(), "selectively disclosed") &&
					!strings.Contains(err.Error(), "hides top-level properties behind _sd") {
					t.Fatalf("refused, but not for the disclosure: %v", err)
				}
				return
			}
			if err := cred.Verify(vc.WithResolver(resolver)); err == nil {
				t.Fatalf("%q outside the signature was accepted: issuer=%v expirationDate=%v credentialStatus=%v",
					tc.path, cred.ExtractField("issuer"),
					cred.ExtractField("expirationDate"), cred.ExtractField("credentialStatus"))
			}
		})
	}
}

// Nothing in the SDK signs the token below; it is written the way an attacker
// would, and the question is only what the verifier makes of it. The entry
// point is ParseCredential, because that is what a consumer calls — a test that
// reaches into jwt.VerifyJWT would not see the routing that picks the
// proofPurpose.
//
// The shape: the attacker signs with its own key, names its own DID in iss and
// kid, and puts the victim's DID in issuer. Judged as a credential this fails,
// because iss must match issuer. Judged as a presentation it passes, because a
// presentation's signer is its holder and issuer is never consulted — and the
// caller then reads a credential whose issuer is the victim.
func TestVC_IssuerForgeryThroughProofPurposeRouting(t *testing.T) {
	const (
		attackerDID = "did:example:attacker"
		victimDID   = "did:example:victim"
	)

	attackerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen attacker key: %v", err)
	}
	victimKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen victim key: %v", err)
	}
	attackerVM := mustP256VM(t, attackerDID, "key-1", &attackerKey.PublicKey)
	victimVM := mustP256VM(t, victimDID, "key-1", &victimKey.PublicKey)
	resolver := vmpkg.NewStaticResolver(
		vmpkg.NewDIDDocument(attackerDID, attackerVM),
		vmpkg.NewDIDDocument(victimDID, victimVM),
	)
	prov, err := signer.NewP256Provider(attackerKey)
	if err != nil {
		t.Fatalf("attacker provider: %v", err)
	}

	for _, tc := range []struct {
		name  string
		typ   string
		types []interface{}
	}{
		{
			// Order must not decide the kind. Taking the first matching entry
			// read this as a presentation, so the signer passed as the holder and
			// issuer was never compared.
			name:  "presentation named before credential",
			typ:   "vc+jwt",
			types: []interface{}{"VerifiablePresentation", "VerifiableCredential"},
		},
		{
			name:  "credential named before presentation",
			typ:   "vc+jwt",
			types: []interface{}{"VerifiableCredential", "VerifiablePresentation"},
		},
		{
			name:  "spelled application/vc+jwt",
			typ:   "application/vc+jwt",
			types: []interface{}{"VerifiablePresentation", "VerifiableCredential"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			header, err := json.Marshal(map[string]interface{}{
				"typ": tc.typ, "alg": "ES256", "kid": attackerVM.ID,
			})
			if err != nil {
				t.Fatalf("marshal header: %v", err)
			}
			body, err := json.Marshal(map[string]interface{}{
				"@context":          []interface{}{"https://www.w3.org/ns/credentials/v2"},
				"type":              tc.types,
				"iss":               attackerDID,
				"issuer":            victimDID,
				"credentialSubject": map[string]interface{}{"id": "did:example:subject", "role": "admin"},
			})
			if err != nil {
				t.Fatalf("marshal body: %v", err)
			}
			signingInput := base64.RawURLEncoding.EncodeToString(header) + "." +
				base64.RawURLEncoding.EncodeToString(body)
			sig, err := jwtpkg.NewJWTSigner(prov).SignString(signingInput)
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			token := signingInput + "." + sig

			// Parse must not be the thing that saves us: these payloads are
			// well-formed credentials, so a refusal here would mean the test
			// stopped exercising the routing.
			cred, err := vc.ParseCredential([]byte(token), vc.WithResolver(resolver))
			if err != nil {
				t.Fatalf("refused at parse, so the purpose routing was never reached: %v", err)
			}
			err = cred.Verify(vc.WithResolver(resolver))
			if err == nil {
				t.Fatalf("a credential signed by %s verified as issued by %s",
					attackerDID, cred.ExtractField("issuer"))
			}
			// It must be refused for naming the wrong signer, an ambiguous kind,
			// or a media type contradicting the payload — not for some unrelated
			// reason that would stop protecting this the moment it changes.
			for _, want := range []string{
				"names both a credential and a presentation",
				"but its payload is a",
				"does not match",
			} {
				if strings.Contains(err.Error(), want) {
					return
				}
			}
			t.Fatalf("refused, but not for the forgery: %v", err)
		})
	}
}
