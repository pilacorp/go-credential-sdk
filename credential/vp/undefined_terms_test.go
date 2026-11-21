package vp_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	"github.com/pilacorp/go-credential-sdk/credential/common/processor"
	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/vp"
)

const (
	undefinedTermsV2Ctx = "https://www.w3.org/ns/credentials/undefined-terms/v2"
	undefinedTermsDID   = "did:nda:testnet:undefined-terms-vp"
)

// noNetworkTransport refuses every request, so a context that is not bundled
// fails the test instead of being fetched.
type noNetworkTransport struct{}

func (noNetworkTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("network access is forbidden: %s", r.URL)
}

// VCDM 2.0 §5.2: undefined-terms/v2 is the last value of @context. A VP that
// names it signs and verifies with no network on P-256 (ecdsa-rdfc-2019) and
// secp256k1 (EcdsaSecp256k1Signature2019), and the suite context the signer
// adds goes before it.
func TestUndefinedTermsV2_VP_SignVerify_NoNetwork(t *testing.T) {
	p256Priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p256Prov, err := signer.NewP256Provider(p256Priv)
	if err != nil {
		t.Fatal(err)
	}
	p256VM, err := verificationmethod.NewP256VM(undefinedTermsDID, "key-p256", &p256Priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	secpPriv, err := ethcrypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	secpProv, err := signer.NewDefaultProvider(hex.EncodeToString(ethcrypto.FromECDSA(secpPriv)))
	if err != nil {
		t.Fatal(err)
	}
	secpVM := verificationmethod.NewSecp256k1VM(undefinedTermsDID, "key-secp",
		hex.EncodeToString(ethcrypto.FromECDSAPub(&secpPriv.PublicKey)))
	resolver := verificationmethod.NewStaticResolver(
		verificationmethod.NewDIDDocument(undefinedTermsDID, p256VM, secpVM))

	processor.SetDocumentLoaderHTTPClient(&http.Client{Transport: noNetworkTransport{}})
	t.Cleanup(func() { processor.SetDocumentLoaderHTTPClient(nil) })

	for _, tc := range []struct {
		name     string
		key      string
		prov     signer.SignerProvider
		suiteCtx string
	}{
		{name: "P-256", key: "key-p256", prov: p256Prov},
		{name: "secp256k1", key: "key-secp", prov: secpProv,
			suiteCtx: "https://w3id.org/security/suites/secp256k1-2019/v1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pres, err := vp.NewJSONPresentation(vp.PresentationContents{
				Context: []interface{}{"https://www.w3.org/ns/credentials/v2", undefinedTermsV2Ctx},
				ID:      "urn:uuid:undefined-terms-vp-" + tc.key,
				Types:   []string{"VerifiablePresentation"},
				Holder:  undefinedTermsDID,
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := pres.AddProofByProvider(tc.prov,
				vp.WithVerificationMethodKey(tc.key), vp.WithResolver(resolver)); err != nil {
				t.Fatalf("sign: %v", err)
			}
			raw, err := pres.Serialize()
			if err != nil {
				t.Fatal(err)
			}
			b, err := json.Marshal(raw)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := vp.ParseJSONPresentation(b)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if err := parsed.Verify(vp.WithResolver(resolver)); err != nil {
				t.Fatalf("verify: %v", err)
			}

			var doc struct {
				Context []string `json:"@context"`
			}
			if err := json.Unmarshal(b, &doc); err != nil {
				t.Fatal(err)
			}
			last := len(doc.Context) - 1
			if last < 1 || doc.Context[last] != undefinedTermsV2Ctx {
				t.Fatalf("@context = %v, want %s last", doc.Context, undefinedTermsV2Ctx)
			}
			if tc.suiteCtx != "" && doc.Context[last-1] != tc.suiteCtx {
				t.Fatalf("@context = %v, want %s just before undefined-terms/v2", doc.Context, tc.suiteCtx)
			}
		})
	}
}
