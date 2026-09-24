package jsonmap

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/pilacorp/go-credential-sdk/credential/common/dto"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
)

// The other direction of the same rule: a header carrying fields this SDK does
// not write is fine, as long as the signature covers it. Refusing those would
// make every proof from another implementation unverifiable here.
func TestSecp256k1Suite_AcceptsAHeaderWithExtraFields(t *testing.T) {
	const did = "did:example:secp-hdr"
	priv, err := ethcrypto.HexToECDSA("59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d")
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	doc := verificationmethod.NewDIDDocument(did, verificationmethod.NewSecp256k1VM(
		did, "key-1", hex.EncodeToString(ethcrypto.CompressPubkey(&priv.PublicKey))))

	m := testCredential()
	if err := (&m).ensureSecp256k1SuiteContext(); err != nil {
		t.Fatalf("context: %v", err)
	}
	proof := &dto.Proof{
		Type:               EcdsaSecp256k1Signature2019,
		Created:            "2026-01-01T00:00:00Z",
		VerificationMethod: did + "#key-1",
		ProofPurpose:       "assertionMethod",
	}

	// A header with kid, the way another implementation might write it.
	headerJSON, err := json.Marshal(map[string]interface{}{
		"alg": AlgES256K, "b64": false, "crit": []string{"b64"}, "kid": did + "#key-1",
	})
	if err != nil {
		t.Fatalf("header: %v", err)
	}
	encHeader := base64.RawURLEncoding.EncodeToString(headerJSON)

	signingInput, err := m.secp256k1SigningInput(proof, encHeader)
	if err != nil {
		t.Fatalf("signing input: %v", err)
	}
	digest := sha256.Sum256(signingInput)
	signature, err := ethcrypto.Sign(digest[:], priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	proof.JWS = encHeader + ".." + base64.RawURLEncoding.EncodeToString(signature[:64])

	ok, err := m.verifyEcdsaSecp256k1Proof(doc, proof)
	if err != nil || !ok {
		t.Fatalf("a correctly signed header with kid was refused: ok=%v err=%v", ok, err)
	}
}

// The @context arrives in every shape JSON-LD allows. Only the two the VC data
// model produces can be extended; the rest are refused rather than guessed at.
func TestEnsureSecp256k1SuiteContext_Shapes(t *testing.T) {
	const narrow = Secp256k1SuiteContextNarrow

	for _, tc := range []struct {
		name    string
		ctx     interface{}
		want    []interface{}
		wantErr string
	}{
		{
			name: "single string becomes an array",
			ctx:  "https://www.w3.org/ns/credentials/v2",
			want: []interface{}{"https://www.w3.org/ns/credentials/v2", narrow},
		},
		{
			name: "array keeps its order and gets the suite last",
			ctx:  []interface{}{"https://www.w3.org/ns/credentials/v2", map[string]interface{}{"@vocab": "https://example.org/v#"}},
			want: []interface{}{"https://www.w3.org/ns/credentials/v2", map[string]interface{}{"@vocab": "https://example.org/v#"}, narrow},
		},
		{
			name: "a document already defining the suite is left alone",
			ctx:  []interface{}{"https://www.w3.org/ns/credentials/v2", narrow},
			want: []interface{}{"https://www.w3.org/ns/credentials/v2", narrow},
		},
		{
			name:    "no @context at all",
			ctx:     nil,
			wantErr: "has no @context",
		},
		{
			name:    "@context as an object",
			ctx:     map[string]interface{}{"@vocab": "https://example.org/v#"},
			wantErr: "unexpected type",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := JSONMap{"id": "urn:uuid:shape"}
			if tc.ctx != nil {
				m["@context"] = tc.ctx
			}
			err := (&m).ensureSecp256k1SuiteContext()
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want one mentioning %q", err, tc.wantErr)
				}

				return
			}
			if err != nil {
				t.Fatalf("ensure: %v", err)
			}
			got, _ := m["@context"].([]interface{})
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("@context = %#v, want %#v", got, tc.want)
			}
		})
	}
}
