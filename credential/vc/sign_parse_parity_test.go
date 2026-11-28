package vc_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
)

// One invariant over every credential builder and a set of awkward claims:
// a credential the SDK signs is one ParseCredential reads back and verifies.
// A builder may refuse the claims, but it must not sign what the reader
// refuses.
func TestEveryBuilderSignsOnlyWhatItParses(t *testing.T) {
	did, priv, resolver := joseSetup(t)
	prov, err := signer.NewP256Provider(priv)
	if err != nil {
		t.Fatal(err)
	}
	nest := func(depth int) interface{} {
		v := interface{}("x")
		for i := 0; i < depth; i++ {
			v = map[string]interface{}{"d": v}
		}
		return v
	}
	digest := "X9yH0Ajrdm1Oij4tWso9UzzKJvPoDxwmuEcO3XAdRC0"
	shapes := map[string]interface{}{
		"plain":            "x",
		"depth 31":         nest(31),
		"depth 33":         nest(33),
		"depth 63":         nest(63),
		"depth 65":         nest(65),
		"_sd string":       map[string]interface{}{"_sd": "x"},
		"_sd array":        map[string]interface{}{"_sd": []interface{}{digest}},
		"... in object":    map[string]interface{}{"...": digest},
		"... in array":     []interface{}{map[string]interface{}{"...": digest}},
		"nested _sd_alg":   map[string]interface{}{"_sd_alg": "sha-256"},
		"int past 2^53":    int64(1)<<53 + 1,
		"html and unicode": "<&> ✓",
		"empty containers": map[string]interface{}{"o": map[string]interface{}{}, "a": []interface{}{}},
		"empty key":        map[string]interface{}{"": "v"},
		"nested arrays":    []interface{}{[]interface{}{"a", []interface{}{"b"}}},
		"typed slice":      []string{"a", "b"},
		"typed map":        map[string]string{"k": "v"},
		// Reserved names inside typed Go values: the builder must read them
		// as the parser does, from the JSON.
		"typed map _sd":      map[string]string{"_sd": "x"},
		"typed map ...":      map[string]string{"...": digest},
		"typed map _sd_alg":  map[string]string{"_sd_alg": "sha-256"},
		"typed slice of ...": []map[string]string{{"...": digest}},
		"slice of map ...":   []map[string]interface{}{{"...": digest}},
		"struct with _sd": struct {
			SD []string `json:"_sd"`
		}{[]string{digest}},
		"raw JSON _sd": json.RawMessage(`{"_sd":["` + digest + `"]}`),
		"raw JSON ...": json.RawMessage(`{"...":"` + digest + `"}`),
	}
	// A disclosure built outside the SDK, its digest left in the contents
	// (the README advanced path).
	pre, err := json.Marshal([]interface{}{"c2FsdHNhbHRzYWx0", "pre", "v"})
	if err != nil {
		t.Fatal(err)
	}
	preDisclosure := base64.RawURLEncoding.EncodeToString(pre)
	preSum := sha256.Sum256([]byte(preDisclosure))
	preDigest := base64.RawURLEncoding.EncodeToString(preSum[:])
	type builder func(vc.CredentialContents) (vc.Credential, error)
	jose := func(extra ...vc.CredentialOpt) builder {
		return func(c vc.CredentialContents) (vc.Credential, error) {
			cred, err := vc.NewJOSECredential(c, append([]vc.CredentialOpt{vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver)}, extra...)...)
			if err != nil {
				return nil, err
			}
			return cred, cred.AddProofByProvider(prov, vc.WithResolver(resolver))
		}
	}
	builders := map[string]builder{
		"prebuilt disclosures only": func(c vc.CredentialContents) (vc.Credential, error) {
			c.Subject[0].CustomFields["_sd"] = []interface{}{preDigest}
			return jose(vc.WithSDDisclosures([]string{preDisclosure}))(c)
		},
		"prebuilt disclosures, _sd as []string": func(c vc.CredentialContents) (vc.Credential, error) {
			c.Subject[0].CustomFields["_sd"] = []string{preDigest}
			return jose(vc.WithSDDisclosures([]string{preDisclosure}))(c)
		},
		"vc+jwt":    jose(),
		"vc+sd-jwt": jose(vc.WithSDSelectivePaths([]string{"credentialSubject.name"})),
		"vc+sd-jwt sha-384 decoys": jose(vc.WithSDSelectivePaths([]string{"credentialSubject.name"}),
			vc.WithSDHashAlgorithm("sha-384"), vc.WithSDDecoyDigests([]vc.Decoy{{Path: "credentialSubject", Count: 2}})),
		"VC-JWT 1.1": func(c vc.CredentialContents) (vc.Credential, error) {
			cred, err := vc.NewJWTCredential(c, vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver))
			if err != nil {
				return nil, err
			}
			return cred, cred.AddProofByProvider(prov, vc.WithResolver(resolver))
		},
	}
	for bname, build := range builders {
		for sname, shape := range shapes {
			t.Run(fmt.Sprintf("%s/%s", bname, sname), func(t *testing.T) {
				c := joseContents(did)
				c.Subject[0].CustomFields["claim"] = shape
				cred, err := build(c)
				// A builder that refuses everything would pass the rest of
				// this test: plain claims must build.
				if sname == "plain" && err != nil {
					t.Fatalf("plain claims refused at build: %v", err)
				}
				if err != nil {
					t.Logf("REFUSED %v", err)
					return // refused at build: nothing unreadable was signed
				}
				s, err := cred.Serialize()
				if err != nil {
					t.Fatalf("signed but cannot serialize: %v", err)
				}
				var raw []byte
				switch v := s.(type) {
				case string:
					raw = []byte(v)
				case []byte:
					raw = v
				default:
					t.Fatalf("Serialize gave %T", s)
				}
				if _, err := vc.ParseCredential(raw, vc.WithResolver(resolver), vc.WithVerifyProof()); err != nil {
					t.Fatalf("signed, then refused by ParseCredential: %v", err)
				}
			})
		}
	}
}
