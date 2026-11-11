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
	"github.com/pilacorp/go-credential-sdk/digitalcredential/statuslist"
	"github.com/pilacorp/go-credential-sdk/jose/jws"
)

const issuerDID = "did:example:issuer"

// resolverFor serves a document with one assertion key over the HTTPS binding.
func resolverFor(t *testing.T, vm map[string]any) *didresolver.Resolver {
	t.Helper()
	return resolverWith(t, vm, nil)
}

// resolverWith is resolverFor with an AcceptKey.
func resolverWith(t *testing.T, vm map[string]any, accept didresolver.AcceptKeyFunc) *didresolver.Resolver {
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
	r, err := didresolver.New(didresolver.Config{URL: srv.URL + "/did/", HTTPClient: srv.Client(), AcceptKey: accept})
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
		if !errors.As(err, &e) || e.Code != dc.CodeIssuerNotSupported || !strings.Contains(err.Error(), "use didresolver") {
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

// A key rotated out is revoked in the document with the reason superseded. By
// default its tokens still verify and those of a compromise do not; an AcceptKey
// that drops the reason keeps CID alone, and one that says no refuses even a
// key in force.
func TestVerifyWithAcceptKey(t *testing.T) {
	revoked := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	cidOnly := func(k didresolver.KeyInfo) bool {
		k.RevocationReason = ""
		return didresolver.DefaultAcceptKey(k)
	}
	no := func(didresolver.KeyInfo) bool { return false }
	for name, tc := range map[string]struct {
		revoked bool
		reason  string
		accept  didresolver.AcceptKeyFunc
		want    dc.Code
	}{
		"rotated, default":            {true, "superseded", nil, ""},
		"rotated, CID alone":          {true, "superseded", cidOnly, dc.CodeIssuerKeyNotFound},
		"retired, default":            {true, "cessationOfOperation", nil, ""},
		"compromise, default":         {true, "keyCompromise", nil, dc.CodeIssuerKeyNotFound},
		"no reason, default":          {true, "", nil, dc.CodeIssuerKeyNotFound},
		"in force, default":           {false, "", nil, ""},
		"in force, AcceptKey says no": {false, "", no, dc.CodeIssuerKeyNotFound},
	} {
		compact, vm := p256Issuer(t)
		if tc.revoked {
			vm["revoked"] = revoked
		}
		if tc.reason != "" {
			vm["revocationReason"] = tc.reason
		}
		_, err := verify(t, resolverWith(t, vm, tc.accept), compact)
		var e *dc.Error
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: %v", name, err)
		case tc.want != "" && (!errors.As(err, &e) || e.Code != tc.want):
			t.Errorf("%s: err = %v; want %s", name, err, tc.want)
		}
	}
}

// A Status List Token whose iss is the DID is verified with the key the DID
// document lists, as a credential is.
func TestCheckerReadsAStatusListOfADIDIssuer(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jws.PrivateKeySigner(priv)
	if err != nil {
		t.Fatal(err)
	}
	b64 := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	vm := map[string]any{"type": "JsonWebKey", "publicKeyJwk": map[string]any{
		"kty": "EC", "crv": "P-256",
		"x": b64(priv.X.FillBytes(make([]byte, 32))),
		"y": b64(priv.Y.FillBytes(make([]byte, 32))),
	}}
	list, err := statuslist.New(16, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := list.Set(3, 1); err != nil {
		t.Fatal(err)
	}
	var token string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/statuslist+jwt")
		w.Write([]byte(token))
	}))
	defer srv.Close()
	uri := srv.URL + "/statuslists/1"
	if token, err = list.IssueToken(context.Background(), statuslist.TokenClaims{
		Sub: uri, IssuedAt: time.Now(), Expiry: time.Now().Add(time.Hour),
		Other: map[string]any{"iss": issuerDID},
	}, issuerkey.SigningKey{Signer: signer, Public: &priv.PublicKey, KID: issuerDID + "#key-1"}); err != nil {
		t.Fatal(err)
	}
	c, err := statuslist.NewChecker(statuslist.Config{Issuers: resolverFor(t, vm), HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	for idx, want := range map[int]uint8{3: 1, 4: 0} {
		if got, err := c.Status(context.Background(), statuslist.Ref{URI: uri, Index: idx}, issuerDID); err != nil || got != want {
			t.Errorf("Status(%d) = %d, %v; want %d", idx, got, err, want)
		}
	}
	_, other := p256Issuer(t)
	c, err = statuslist.NewChecker(statuslist.Config{Issuers: resolverFor(t, other), HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Status(context.Background(), statuslist.Ref{URI: uri, Index: 3}, issuerDID); err == nil {
		t.Error("a token signed by a key the document does not list was accepted")
	}
}
