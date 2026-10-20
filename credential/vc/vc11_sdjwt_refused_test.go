package vc_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/pilacorp/go-credential-sdk/credential/common/sdjwt"
	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	vmpkg "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
	"github.com/pilacorp/go-credential-sdk/credential/vp"
)

// Both fixtures were produced by v1.13.1 from vc11FixtureContents, signed with
// vc11FixtureKey under did:example:issuer-100#key-1.

// v1131PlainSigningInput is the header.payload v1.13.1 built for a plain VC 1.1
// JWT. #100 must not move it by a byte: authen-service anchors credentials by
// Hash(), so a different serialization would be a different anchor.
const v1131PlainSigningInput = "eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDpleGFtcGxlOmlzc3Vlci0xMDAja2V5LTEiLCJ0eXAiOiJKV1QifQ.eyJpYXQiOjE3NjcyMjU2MDAsImlzcyI6ImRpZDpleGFtcGxlOmlzc3Vlci0xMDAiLCJqdGkiOiJ1cm46dXVpZDpmaXh0dXJlLTEwMCIsIm5iZiI6MTc2NzIyNTYwMCwic3ViIjoiZGlkOmV4YW1wbGU6c3ViamVjdCIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImJsb29kVHlwZSI6Ik8tIiwiaWQiOiJkaWQ6ZXhhbXBsZTpzdWJqZWN0IiwibmFtZSI6IkFsaWNlIn0sImlkIjoidXJuOnV1aWQ6Zml4dHVyZS0xMDAiLCJpc3N1ZXIiOiJkaWQ6ZXhhbXBsZTppc3N1ZXItMTAwIiwidHlwZSI6IlZlcmlmaWFibGVDcmVkZW50aWFsIiwidmFsaWRGcm9tIjoiMjAyNi0wMS0wMVQwMDowMDowMFoifX0"

// v1131SDJWT is a VC 1.1 SD-JWT as v1.13.1 issued it: typ "JWT", _sd_alg and
// _sd under the vc claim, bloodType disclosed after the "~".
const v1131SDJWT = "eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDpleGFtcGxlOmlzc3Vlci0xMDAja2V5LTEiLCJ0eXAiOiJKV1QifQ.eyJpYXQiOjE3NjcyMjU2MDAsImlzcyI6ImRpZDpleGFtcGxlOmlzc3Vlci0xMDAiLCJqdGkiOiJ1cm46dXVpZDpmaXh0dXJlLTEwMCIsIm5iZiI6MTc2NzIyNTYwMCwic3ViIjoiZGlkOmV4YW1wbGU6c3ViamVjdCIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sIl9zZF9hbGciOiJzaGEtMjU2IiwiY3JlZGVudGlhbFN1YmplY3QiOnsiX3NkIjpbIm1IQUNvTWRXWlNRVlR0VzRUaWZaZmxjdFFmdXpGV0J5djdHakRLc1NBVmsiXSwiaWQiOiJkaWQ6ZXhhbXBsZTpzdWJqZWN0IiwibmFtZSI6IkFsaWNlIn0sImlkIjoidXJuOnV1aWQ6Zml4dHVyZS0xMDAiLCJpc3N1ZXIiOiJkaWQ6ZXhhbXBsZTppc3N1ZXItMTAwIiwidHlwZSI6IlZlcmlmaWFibGVDcmVkZW50aWFsIiwidmFsaWRGcm9tIjoiMjAyNi0wMS0wMVQwMDowMDowMFoifX0.sxJUM-F2eqllXcqIxOk3uJAmW8WWxA1yaR11zuZ6m8Arh5_BD-3X_z-eKU8xdLkaGVhsuc8f2Pvxw9Zbh-1k9w~WyJnU1dreU9MZW1TSDFhcnFfZWpWWG13IiwiYmxvb2RUeXBlIiwiTy0iXQ~"

func vc11FixtureKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	d, ok := new(big.Int).SetString("6f2e3a8c1b9d4e7f0a1c2b3d4e5f60718293a4b5c6d7e8f90112233445566778", 16)
	if !ok {
		t.Fatal("bad fixture scalar")
	}
	k := &ecdsa.PrivateKey{D: d}
	k.PublicKey.Curve = elliptic.P256()
	k.PublicKey.X, k.PublicKey.Y = elliptic.P256().ScalarBaseMult(d.Bytes())
	return k
}

const vc11FixtureDID = "did:example:issuer-100"

func vc11FixtureResolver(t *testing.T) vmpkg.ResolverProvider {
	t.Helper()
	vm, err := vmpkg.NewP256MultikeyVM(vc11FixtureDID, "key-1", &vc11FixtureKey(t).PublicKey)
	if err != nil {
		t.Fatalf("multikey vm: %v", err)
	}
	return vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(vc11FixtureDID, vm))
}

func vc11FixtureContents(t *testing.T) vc.CredentialContents {
	t.Helper()
	validFrom, err := time.Parse(time.RFC3339, "2026-01-01T00:00:00Z")
	if err != nil {
		t.Fatalf("parse time: %v", err)
	}
	return vc.CredentialContents{
		Context:   []interface{}{"https://www.w3.org/2018/credentials/v1"},
		ID:        "urn:uuid:fixture-100",
		Issuer:    vc11FixtureDID,
		Types:     []string{"VerifiableCredential"},
		ValidFrom: validFrom,
		Subject: []vc.Subject{{ID: "did:example:subject", CustomFields: map[string]interface{}{
			"name": "Alice", "bloodType": "O-",
		}}},
	}
}

// countingResolver records every DID it is asked for, so a test can show a
// refusal happened before the network would have been touched.
type countingResolver struct {
	inner vmpkg.ResolverProvider
	calls int
}

func (r *countingResolver) ResolveDocument(ctx context.Context, did string) (*vmpkg.DIDDocument, error) {
	r.calls++
	return r.inner.ResolveDocument(ctx, did)
}

// Every SD option is refused on the VC 1.1 path, before the DID is resolved.
func TestVC11_NewJWTCredentialRefusesSDOptions(t *testing.T) {
	for _, tc := range []struct {
		name string
		opt  vc.CredentialOpt
	}{
		{"WithSDSelectivePaths", vc.WithSDSelectivePaths([]string{"credentialSubject.bloodType"})},
		{"WithSDDisclosures", vc.WithSDDisclosures([]string{"WyJzYWx0IiwibmFtZSIsIkEiXQ"})},
		{"WithSDDecoyDigests", vc.WithSDDecoyDigests([]vc.Decoy{{Path: "credentialSubject", Count: 1}})},
		{"WithSDHashAlgorithm", vc.WithSDHashAlgorithm("sha-256")},
		{"WithSDShuffle", vc.WithSDShuffle(true)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolver := &countingResolver{inner: vc11FixtureResolver(t)}
			_, err := vc.NewJWTCredential(vc11FixtureContents(t),
				vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver), tc.opt)
			if !errors.Is(err, vc.ErrSDJWTRequiresJOSE) {
				t.Fatalf("err = %v, want ErrSDJWTRequiresJOSE", err)
			}
			if resolver.calls != 0 {
				t.Errorf("the DID was resolved %d times for a call that was always going to fail", resolver.calls)
			}
		})
	}
}

// Contents that already carry digests are refused even with no SD option: a
// caller who ran sdjwt.BuildDisclosures itself passes none. Building them would
// produce a typ "JWT" token carrying digests that ParseJWTCredential refuses.
func TestVC11_NewJWTCredentialRefusesContentsCarryingDigests(t *testing.T) {
	res, err := sdjwt.BuildDisclosures(sdjwt.BuildDisclosuresInput{
		VC: map[string]interface{}{"credentialSubject": map[string]interface{}{
			"id": "did:example:subject", "name": "Alice", "bloodType": "O-",
			"emails": []interface{}{"a@example.com", "b@example.com"},
		}},
		SelectivePaths: []string{"credentialSubject.bloodType", "credentialSubject.emails[1]"},
	})
	if err != nil {
		t.Fatalf("build disclosures: %v", err)
	}
	processed, ok := res.ProcessedVC["credentialSubject"].(map[string]interface{})
	if !ok {
		t.Fatalf("processed subject is %T", res.ProcessedVC["credentialSubject"])
	}

	for _, tc := range []struct {
		name   string
		custom map[string]interface{}
	}{
		// An _sd array in credentialSubject: the shape the README used to teach.
		{"_sd in credentialSubject", map[string]interface{}{"name": "Alice", "_sd": processed["_sd"]}},
		// An array element replaced by its {"...": digest} placeholder.
		{"array element placeholder", map[string]interface{}{"emails": processed["emails"]}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			contents := vc11FixtureContents(t)
			contents.Subject = []vc.Subject{{ID: "did:example:subject", CustomFields: tc.custom}}
			resolver := &countingResolver{inner: vc11FixtureResolver(t)}

			_, err := vc.NewJWTCredential(contents, vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver))
			if !errors.Is(err, vc.ErrSDJWTRequiresJOSE) {
				t.Fatalf("err = %v, want ErrSDJWTRequiresJOSE", err)
			}
			if resolver.calls != 0 {
				t.Errorf("the DID was resolved %d times for a call that was always going to fail", resolver.calls)
			}
		})
	}
}

// A plain VC 1.1 JWT is unchanged byte for byte against what v1.13.1 built.
func TestVC11_PlainJWTIsUnchangedSinceV1131(t *testing.T) {
	cred, err := vc.NewJWTCredential(vc11FixtureContents(t),
		vc.WithVerificationMethodKey("key-1"), vc.WithResolver(vc11FixtureResolver(t)))
	if err != nil {
		t.Fatalf("NewJWTCredential: %v", err)
	}
	input, err := cred.GetSigningInput()
	if err != nil {
		t.Fatalf("GetSigningInput: %v", err)
	}
	if string(input) != v1131PlainSigningInput {
		t.Errorf("header.payload changed since v1.13.1:\n got %s\nwant %s", input, v1131PlainSigningInput)
	}

	// And it still signs, round-trips and verifies.
	prov, err := signer.NewP256Provider(vc11FixtureKey(t))
	if err != nil {
		t.Fatalf("p256 provider: %v", err)
	}
	if err := cred.AddProofByProvider(prov); err != nil {
		t.Fatalf("sign: %v", err)
	}
	token, err := cred.Serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	parsed, err := vc.ParseCredential([]byte(token.(string)), vc.WithResolver(vc11FixtureResolver(t)))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := parsed.Verify(vc.WithResolver(vc11FixtureResolver(t))); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

// An SD-JWT over VC 1.1 issued by v1.13.1 is refused on every path that reaches
// the 1.1 parser.
func TestVC11_SDJWTFromV1131IsRefused(t *testing.T) {
	t.Run("ParseJWTCredential", func(t *testing.T) {
		if _, err := vc.ParseJWTCredential(v1131SDJWT); !errors.Is(err, vc.ErrSDJWTRequiresJOSE) {
			t.Fatalf("err = %v, want ErrSDJWTRequiresJOSE", err)
		}
	})
	t.Run("ParseCredential", func(t *testing.T) {
		if _, err := vc.ParseCredential([]byte(v1131SDJWT)); !errors.Is(err, vc.ErrSDJWTRequiresJOSE) {
			t.Fatalf("err = %v, want ErrSDJWTRequiresJOSE", err)
		}
	})
	// Credentials inside a presentation are parsed when the presentation is
	// verified with WithVCValidation.
	t.Run("inside a presentation", func(t *testing.T) {
		raw, err := json.Marshal(map[string]interface{}{
			"@context":             []interface{}{"https://www.w3.org/ns/credentials/v2"},
			"type":                 []interface{}{"VerifiablePresentation"},
			"verifiableCredential": []interface{}{v1131SDJWT},
		})
		if err != nil {
			t.Fatalf("marshal vp: %v", err)
		}
		_, err = vp.ParsePresentation(raw, vp.WithVCValidation(), vp.WithResolver(vc11FixtureResolver(t)))
		if !errors.Is(err, vc.ErrSDJWTRequiresJOSE) {
			t.Fatalf("err = %v, want ErrSDJWTRequiresJOSE", err)
		}
	})
}

// _sd_alg marks a token as an SD-JWT on its own, with no digest and no "~". It is
// looked for in both places it can sit: at the payload root, where RFC 9901
// § 4.1.1 puts it and where another implementation's token would carry it, and
// inside vc, where this SDK used to write it.
func TestVC11_SDAlgIsRefusedWhereverItSits(t *testing.T) {
	prov, err := signer.NewP256Provider(vc11FixtureKey(t))
	if err != nil {
		t.Fatalf("p256 provider: %v", err)
	}
	vcClaim := func(withAlg bool) map[string]interface{} {
		m := map[string]interface{}{
			"@context":          []interface{}{"https://www.w3.org/2018/credentials/v1"},
			"type":              []interface{}{"VerifiableCredential"},
			"issuer":            vc11FixtureDID,
			"issuanceDate":      "2026-01-01T00:00:00Z",
			"credentialSubject": map[string]interface{}{"id": "did:example:subject", "name": "Alice"},
		}
		if withAlg {
			m["_sd_alg"] = "sha-256"
		}
		return m
	}

	for _, tc := range []struct {
		name    string
		payload map[string]interface{}
	}{
		{"at the payload root", map[string]interface{}{"iss": vc11FixtureDID, "_sd_alg": "sha-256", "vc": vcClaim(false)}},
		{"inside vc", map[string]interface{}{"iss": vc11FixtureDID, "vc": vcClaim(true)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			token := signJOSEByHand(t, prov, "JWT", vc11FixtureDID+"#key-1", tc.payload)
			if _, err := vc.ParseCredential([]byte(token)); !errors.Is(err, vc.ErrSDJWTRequiresJOSE) {
				t.Fatalf("err = %v, want ErrSDJWTRequiresJOSE", err)
			}
		})
	}
}

// DecodedDisclosures keeps answering as it did for a plain JWT — an empty,
// non-nil slice and no error — so a caller asking it of every credential does
// not break. Present has nothing to choose from and says so.
func TestVC11_DecodedDisclosuresAndPresent(t *testing.T) {
	cred, err := vc.NewJWTCredential(vc11FixtureContents(t),
		vc.WithVerificationMethodKey("key-1"), vc.WithResolver(vc11FixtureResolver(t)))
	if err != nil {
		t.Fatalf("NewJWTCredential: %v", err)
	}
	prov, err := signer.NewP256Provider(vc11FixtureKey(t))
	if err != nil {
		t.Fatalf("p256 provider: %v", err)
	}
	if err := cred.AddProofByProvider(prov); err != nil {
		t.Fatalf("sign: %v", err)
	}

	decoded, err := cred.DecodedDisclosures()
	if err != nil {
		t.Errorf("DecodedDisclosures err = %v, want nil", err)
	}
	if decoded == nil || len(decoded) != 0 {
		t.Errorf("DecodedDisclosures = %#v, want an empty non-nil slice", decoded)
	}

	if _, err := cred.Present(nil); !errors.Is(err, vc.ErrSDJWTRequiresJOSE) {
		t.Errorf("Present err = %v, want ErrSDJWTRequiresJOSE", err)
	}
}
