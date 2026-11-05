package didresolver_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	dc "github.com/pilacorp/go-credential-sdk/digitalcredential"
	"github.com/pilacorp/go-credential-sdk/digitalcredential/didresolver"
	"github.com/pilacorp/go-credential-sdk/digitalcredential/issuerkey"
	"github.com/pilacorp/go-credential-sdk/digitalcredential/issuermeta"
	"github.com/pilacorp/go-credential-sdk/jose/jws"
)

const issuerDID = "did:example:issuer"

// resolverFor serves a document with one assertion key over the HTTPS binding.
func resolverFor(t *testing.T, vm map[string]any) *didresolver.Resolver {
	t.Helper()
	vm["id"], vm["controller"] = issuerDID+"#key-1", issuerDID
	body, err := json.Marshal(map[string]any{
		"id":                 issuerDID,
		"verificationMethod": []any{vm},
		"assertionMethod":    []any{issuerDID + "#key-1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/"+issuerDID) {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	t.Cleanup(srv.Close)
	r, err := didresolver.New(didresolver.Config{URL: srv.URL + "/did/", HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// issue signs a credential whose iss is the DID and whose kid is absolute.
func issue(t *testing.T, signer jws.Signer, public crypto.PublicKey) string {
	t.Helper()
	cred, err := dc.Issue(context.Background(), dc.IssueRequest{
		Issuer: issuerDID,
		VCT:    "https://credentials.example/identity_credential",
		Expiry: time.Now().Add(time.Hour),
		Claims: map[string]any{"given_name": "Erika"},
	}, issuerkey.SigningKey{Signer: signer, Public: public, KID: issuerDID + "#key-1"})
	if err != nil {
		t.Fatal(err)
	}
	return cred.Serialize()
}

func verify(t *testing.T, r issuerkey.Resolver, compact string) (*dc.Result, error) {
	t.Helper()
	cred, err := dc.Parse(compact)
	if err != nil {
		t.Fatal(err)
	}
	return cred.Verify(context.Background(), r, dc.WithoutStatusCheck(), dc.WithKeyBinding(dc.KeyBindingNotRequired))
}

func p256Issuer(t *testing.T) (compact string, vm map[string]any) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jws.PrivateKeySigner(priv)
	if err != nil {
		t.Fatal(err)
	}
	b64 := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	return issue(t, signer, &priv.PublicKey), map[string]any{"type": "JsonWebKey", "publicKeyJwk": map[string]any{
		"kty": "EC", "crv": "P-256",
		"x": b64(priv.X.FillBytes(make([]byte, 32))),
		"y": b64(priv.Y.FillBytes(make([]byte, 32))),
	}}
}

func secp256k1Issuer(t *testing.T) (compact string, vm map[string]any) {
	t.Helper()
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jws.PrivateKeySigner(priv.ToECDSA())
	if err != nil {
		t.Fatal(err)
	}
	return issue(t, signer, &priv.ToECDSA().PublicKey), map[string]any{
		"type":         "EcdsaSecp256k1VerificationKey2019",
		"publicKeyHex": hex.EncodeToString(priv.PubKey().SerializeCompressed()),
	}
}

func TestVerifyCredentialOfADIDIssuer(t *testing.T) {
	for name, make := range map[string]func(*testing.T) (string, map[string]any){
		"P-256":     p256Issuer,
		"secp256k1": secp256k1Issuer,
	} {
		compact, vm := make(t)
		res, err := verify(t, resolverFor(t, vm), compact)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if res.Issuer != issuerDID {
			t.Errorf("%s: Issuer = %q", name, res.Issuer)
		}
	}
}

// The key in the document decides: a credential signed by any other key fails.
func TestVerifyRefusesAKeyTheDocumentDoesNotHold(t *testing.T) {
	compact, _ := p256Issuer(t)
	_, vm := p256Issuer(t)
	var e *dc.Error
	if _, err := verify(t, resolverFor(t, vm), compact); !errors.As(err, &e) || e.Code != dc.CodeSignatureInvalid {
		t.Errorf("err = %v; want %s", err, dc.CodeSignatureInvalid)
	}
}

// A consumer who reads only https issuers changes nothing, and the error on a
// DID says what to supply, through Multi as well as alone.
func TestVerifyTellsTheConsumerToSupplyADIDResolver(t *testing.T) {
	compact, _ := p256Issuer(t)
	meta, err := issuermeta.NewResolver(issuermeta.Config{})
	if err != nil {
		t.Fatal(err)
	}
	multi, err := issuerkey.Multi(meta)
	if err != nil {
		t.Fatal(err)
	}
	for name, r := range map[string]issuerkey.Resolver{"alone": meta, "in Multi": multi} {
		_, err := verify(t, r, compact)
		var e *dc.Error
		if !errors.As(err, &e) || e.Code != dc.CodeIssuerNotSupported || !strings.Contains(err.Error(), "didresolver.New") {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestMultiReadsBothKindsOfIssuer(t *testing.T) {
	compact, vm := p256Issuer(t)
	meta, err := issuermeta.NewResolver(issuermeta.Config{})
	if err != nil {
		t.Fatal(err)
	}
	r, err := issuerkey.Multi(meta, resolverFor(t, vm))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = verify(t, r, compact); err != nil {
		t.Error(err)
	}
}
