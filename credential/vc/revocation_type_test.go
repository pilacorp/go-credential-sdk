package vc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	credentialstatus "github.com/pilacorp/go-credential-sdk/credential/common/credential-status"
	"github.com/pilacorp/go-credential-sdk/credential/common/jsonmap"
	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	"github.com/pilacorp/go-credential-sdk/credential/common/util"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
)

// TC-B02: a credentialStatus with an unknown type is ignored by
// checkRevocation. The old code required statusListCredential, failing with
// "credentialStatus.statusListCredential is required".
func TestCheckRevocation_UnknownTypeSingleObject(t *testing.T) {
	c := CredentialData{
		"credentialStatus": map[string]interface{}{
			"type": "UnknownStatusType",
			"id":   "https://example.org/status/1",
		},
	}
	if err := checkRevocation(c, nil, false); err != nil {
		t.Fatalf("checkRevocation = %v, want nil (unknown type ignored)", err)
	}
}

// TC-B01: an array with one known and one unknown type. The unknown entry is
// skipped; the known entry is checked normally against a signed status list.
// We verify that the unknown entry does not cause "must be an object" and that
// the known entry's revocation check succeeds.
func TestCheckRevocation_ArrayWithUnknownType(t *testing.T) {
	const issuerDID = "did:example:revocation-type"
	srv, resolver := signedNotRevokedStatusListServer(t, issuerDID)

	c := CredentialData{
		"issuer": issuerDID,
		"credentialStatus": []interface{}{
			map[string]interface{}{
				"type": "UnknownStatusType",
				"id":   "https://example.org/status/x",
			},
			map[string]interface{}{
				"type":                 "BitstringStatusListEntry",
				"id":                   srv.URL + "/status/0#1",
				"statusListCredential": srv.URL,
				"statusListIndex":      "1",
				"statusPurpose":        "revocation",
			},
		},
	}
	if err := checkRevocation(c, resolver, true); err != nil {
		t.Fatalf("checkRevocation (known + unknown) = %v, want nil", err)
	}
}

// signedNotRevokedStatusListServer serves a status list credential signed by
// issuerDID with no bits set (nothing revoked), and returns the resolver that
// holds the issuer's key. The status client only reads a signed list, so the
// list carries an ecdsa-rdfc-2019 proof like the one authen-service issues.
func signedNotRevokedStatusListServer(t *testing.T, issuerDID string) (*httptest.Server, verificationmethod.ResolverProvider) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen p256: %v", err)
	}
	vm, err := verificationmethod.NewP256VM(issuerDID, "key-1", &priv.PublicKey)
	if err != nil {
		t.Fatalf("NewP256VM: %v", err)
	}
	resolver := verificationmethod.NewStaticResolver(verificationmethod.NewDIDDocument(issuerDID, vm))

	encoded, err := util.CompressToBase64URL(make([]byte, 16)) // all zero — nothing revoked
	if err != nil {
		t.Fatalf("compress status list: %v", err)
	}
	now := time.Now().UTC()
	list := jsonmap.JSONMap{
		"@context":   []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":       []interface{}{"VerifiableCredential", "BitstringStatusListCredential"},
		"id":         issuerDID + "/status/0",
		"issuer":     issuerDID,
		"validFrom":  now.Add(-time.Hour).Format(time.RFC3339),
		"validUntil": now.Add(24 * time.Hour).Format(time.RFC3339),
		"credentialSubject": map[string]interface{}{
			"id":            issuerDID + "/status/0#list",
			"type":          "BitstringStatusList",
			"statusPurpose": "revocation",
			"encodedList":   encoded,
		},
	}
	sp, err := signer.NewP256Provider(priv)
	if err != nil {
		t.Fatalf("NewP256Provider: %v", err)
	}
	if err := list.AddECDSAProof(sp, issuerDID+"#key-1", "assertionMethod"); err != nil {
		t.Fatalf("sign status list: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}(list)}); err != nil {
			t.Errorf("encode status list: %v", err)
		}
	}))
	t.Cleanup(srv.Close)

	// The default client refuses loopback addresses; the test server lives there.
	credentialstatus.SetDefaultHTTPClient(&http.Client{Timeout: 10 * time.Second})
	t.Cleanup(func() { credentialstatus.SetDefaultHTTPClient(nil) })

	return srv, resolver
}

// The old code rejected an array outright: "credentialStatus must be an object".
func TestCheckRevocation_ArrayAccepted(t *testing.T) {
	c := CredentialData{
		"credentialStatus": []interface{}{
			map[string]interface{}{
				"type": "SomeUnknown",
				"id":   "https://example.org/status/1",
			},
			map[string]interface{}{
				"type": "AnotherUnknown",
				"id":   "https://example.org/status/2",
			},
		},
	}
	if err := checkRevocation(c, nil, false); err != nil {
		t.Fatalf("checkRevocation = %v, want nil (all unknown)", err)
	}
}

// An empty array should return success.
func TestCheckRevocation_EmptyArray(t *testing.T) {
	c := CredentialData{
		"credentialStatus": []interface{}{},
	}
	if err := checkRevocation(c, nil, false); err != nil {
		t.Fatalf("checkRevocation = %v, want nil (empty array)", err)
	}
}
