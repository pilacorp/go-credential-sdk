package vc_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
)

// #105: a credential that builds must also parse. The build side used to look
// for SD-JWT digests in the Go map built from CredentialContents, the parse
// side in the map decoded from the token's JSON. A typed Go value (a
// map[string][]string, a []map, a json.RawMessage) marshals to the same JSON as
// its map[string]interface{} form, but the build-side walk did not see inside
// it, so the credential signed and the SDK then refused it on parse.

// sdShapedValues are values that each marshal to JSON carrying SD-JWT
// machinery: an _sd array, or an array element {"...": digest}.
func sdShapedValues() map[string]interface{} {
	return map[string]interface{}{
		"map[string]interface{} _sd":        map[string]interface{}{"_sd": []interface{}{"abc"}},
		"map[string][]string _sd":           map[string][]string{"_sd": {"abc"}},
		"[]map[string]interface{} ellipsis": []map[string]interface{}{{"...": "abc"}},
		"json.RawMessage _sd":               json.RawMessage(`{"_sd":["abc"]}`),
		"struct with an _sd tag": struct {
			SD []string `json:"_sd"`
		}{SD: []string{"abc"}},
		"[]interface{} ellipsis (plain map)": []interface{}{map[string]interface{}{"...": "abc"}},
	}
}

func contentsWithX(contents vc.CredentialContents, x interface{}) vc.CredentialContents {
	fields := map[string]interface{}{}
	for k, v := range contents.Subject[0].CustomFields {
		fields[k] = v
	}
	fields["x"] = x
	contents.Subject = []vc.Subject{{ID: contents.Subject[0].ID, CustomFields: fields}}
	return contents
}

func v2FixtureContents(t *testing.T) vc.CredentialContents {
	t.Helper()
	contents := vc11FixtureContents(t)
	contents.Context = []interface{}{"https://www.w3.org/ns/credentials/v2"}
	return contents
}

// signAndSerialize signs cred with the fixture key and returns the token.
func signAndSerialize(t *testing.T, cred vc.Credential) string {
	t.Helper()
	prov, err := signer.NewP256Provider(vc11FixtureKey(t))
	if err != nil {
		t.Fatal(err)
	}
	signable, ok := cred.(interface {
		AddProofByProvider(signer.SignerProvider, ...vc.CredentialOpt) error
	})
	if !ok {
		t.Fatalf("%T cannot sign with a provider", cred)
	}
	if err := signable.AddProofByProvider(prov, vc.WithResolver(vc11FixtureResolver(t))); err != nil {
		t.Fatalf("sign: %v", err)
	}
	serialized, err := cred.Serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return serialized.(string)
}

func TestNewJWTCredential_RefusesSDMachineryInTypedValues(t *testing.T) {
	for name, x := range sdShapedValues() {
		t.Run(name, func(t *testing.T) {
			_, err := vc.NewJWTCredential(contentsWithX(vc11FixtureContents(t), x),
				vc.WithResolver(vc11FixtureResolver(t)))
			if !errors.Is(err, vc.ErrSDJWTRequiresJOSE) {
				t.Fatalf("NewJWTCredential error = %v, want ErrSDJWTRequiresJOSE", err)
			}
		})
	}
}

func TestNewJOSECredential_RefusesSubjectDigestsWithoutSD(t *testing.T) {
	for name, x := range sdShapedValues() {
		t.Run(name, func(t *testing.T) {
			_, err := vc.NewJOSECredential(contentsWithX(v2FixtureContents(t), x),
				vc.WithResolver(vc11FixtureResolver(t)))
			if err == nil {
				t.Fatal("NewJOSECredential built a vc+jwt whose credentialSubject carries SD-JWT digests")
			}
			if !strings.Contains(err.Error(), "does not declare SD-JWT") {
				t.Fatalf("error = %q, want it to say the token does not declare SD-JWT", err)
			}
		})
	}
}

// WithSDHashAlgorithm alone names a hash but makes nothing disclosable, so the
// token is vc+jwt and the parser does not exempt the subject. The build side
// must decide the exemption from the same fact, not from "an SD option was set".
func TestNewJOSECredential_HashAlgorithmAloneDoesNotExemptSubject(t *testing.T) {
	_, err := vc.NewJOSECredential(
		contentsWithX(v2FixtureContents(t), map[string]interface{}{"_sd": []interface{}{"abc"}}),
		vc.WithSDHashAlgorithm("sha-256"), vc.WithResolver(vc11FixtureResolver(t)))
	if err == nil {
		t.Fatal("NewJOSECredential built a vc+jwt whose credentialSubject carries SD-JWT digests")
	}
	if !strings.Contains(err.Error(), "does not declare SD-JWT") {
		t.Fatalf("error = %q, want it to say the token does not declare SD-JWT", err)
	}
}

// The converse, which is the rule itself: for every value, with and without
// selective disclosure, a credential that builds also parses.
func TestBuildThenParse_NeverDisagree(t *testing.T) {
	builders := map[string]func(t *testing.T, x interface{}) (vc.Credential, error){
		"VC 1.1 JWT": func(t *testing.T, x interface{}) (vc.Credential, error) {
			return vc.NewJWTCredential(contentsWithX(vc11FixtureContents(t), x),
				vc.WithResolver(vc11FixtureResolver(t)))
		},
		"vc+jwt": func(t *testing.T, x interface{}) (vc.Credential, error) {
			return vc.NewJOSECredential(contentsWithX(v2FixtureContents(t), x),
				vc.WithResolver(vc11FixtureResolver(t)))
		},
		"vc+jwt with WithSDHashAlgorithm only": func(t *testing.T, x interface{}) (vc.Credential, error) {
			return vc.NewJOSECredential(contentsWithX(v2FixtureContents(t), x),
				vc.WithSDHashAlgorithm("sha-256"), vc.WithResolver(vc11FixtureResolver(t)))
		},
		"vc+sd-jwt": func(t *testing.T, x interface{}) (vc.Credential, error) {
			return vc.NewJOSECredential(contentsWithX(v2FixtureContents(t), x),
				vc.WithSDSelectivePaths([]string{"credentialSubject.name"}),
				vc.WithResolver(vc11FixtureResolver(t)))
		},
	}
	values := sdShapedValues()
	values["plain string"] = "no digests here"
	for bName, build := range builders {
		for vName, x := range values {
			t.Run(bName+"/"+vName, func(t *testing.T) {
				cred, err := build(t, x)
				if err != nil {
					return // refused at build: nothing reaches a verifier
				}
				token := signAndSerialize(t, cred)
				if _, err := vc.ParseCredential([]byte(token),
					vc.WithResolver(vc11FixtureResolver(t)), vc.WithVerifyProof()); err != nil {
					t.Fatalf("built and signed, then refused on parse: %v", err)
				}
			})
		}
	}
}

// vc+sd-jwt keeps working, and a plain VC 1.1 JWT keeps the exact bytes v1.13.1
// produced (Hash() is what authen-service anchors).
func TestBuildCheck_SDJWTAndPlainBytesUnchanged(t *testing.T) {
	cred, err := vc.NewJOSECredential(v2FixtureContents(t),
		vc.WithSDSelectivePaths([]string{"credentialSubject.bloodType"}),
		vc.WithResolver(vc11FixtureResolver(t)))
	if err != nil {
		t.Fatalf("vc+sd-jwt build: %v", err)
	}
	token := signAndSerialize(t, cred)
	if _, err := vc.ParseCredential([]byte(token), vc.WithResolver(vc11FixtureResolver(t)), vc.WithVerifyProof()); err != nil {
		t.Fatalf("vc+sd-jwt parse: %v", err)
	}

	plain, err := vc.NewJWTCredential(vc11FixtureContents(t), vc.WithResolver(vc11FixtureResolver(t)))
	if err != nil {
		t.Fatal(err)
	}
	plainToken := signAndSerialize(t, plain)
	if got := plainToken[:strings.LastIndex(plainToken, ".")]; got != v1131PlainSigningInput {
		t.Fatalf("VC 1.1 signing input moved:\n got %s\nwant %s", got, v1131PlainSigningInput)
	}
}

// A large integer must reach the token as the caller wrote it. Checking the
// JSON form must not round-trip what gets signed through float64.
func TestBuildCheck_LargeIntegerSignedAsWritten(t *testing.T) {
	const big = int64(9007199254740993) // 2^53 + 1: not representable as float64
	for name, build := range map[string]func(vc.CredentialContents) (vc.Credential, error){
		"VC 1.1 JWT": func(c vc.CredentialContents) (vc.Credential, error) {
			return vc.NewJWTCredential(c, vc.WithResolver(vc11FixtureResolver(t)))
		},
		"vc+jwt": func(c vc.CredentialContents) (vc.Credential, error) {
			c.Context = []interface{}{"https://www.w3.org/ns/credentials/v2"}
			return vc.NewJOSECredential(c, vc.WithResolver(vc11FixtureResolver(t)))
		},
	} {
		t.Run(name, func(t *testing.T) {
			cred, err := build(contentsWithX(vc11FixtureContents(t), big))
			if err != nil {
				t.Fatal(err)
			}
			token := signAndSerialize(t, cred)
			payload := strings.Split(token, ".")[1]
			raw, err := base64.RawURLEncoding.DecodeString(payload)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(raw), `"x":9007199254740993`) {
				t.Fatalf("payload does not carry the integer as written: %s", raw)
			}
		})
	}
}
