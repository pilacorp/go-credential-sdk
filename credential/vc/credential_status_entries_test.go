package vc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	credentialstatus "github.com/pilacorp/go-credential-sdk/credential/common/credential-status"
	"github.com/pilacorp/go-credential-sdk/credential/common/jsonmap"
	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	"github.com/pilacorp/go-credential-sdk/credential/common/util"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
)

const entriesIssuer = "did:example:status-issuer"

// serveSignedStatusList serves one signed revocation list with the given bits
// set, and counts how many times it is fetched.
func serveSignedStatusList(t *testing.T, set ...int) (url string, resolver verificationmethod.ResolverProvider, hits *atomic.Int32) {
	t.Helper()
	return serveStatusList(t, 1, set...)
}

// serveStatusList is serveSignedStatusList with a proof set of the given size.
func serveStatusList(t *testing.T, proofs int, set ...int) (url string, resolver verificationmethod.ResolverProvider, hits *atomic.Int32) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	vm, err := verificationmethod.NewP256VM(entriesIssuer, "key-1", &priv.PublicKey)
	require.NoError(t, err)
	resolver = verificationmethod.NewStaticResolver(verificationmethod.NewDIDDocument(entriesIssuer, vm))

	bits := make([]byte, 16384)
	for _, pos := range set {
		bits[pos/8] |= 1 << uint(7-pos%8)
	}
	encoded, err := util.CompressToBase64URL(bits)
	require.NoError(t, err)

	now := time.Now().UTC()
	list := jsonmap.JSONMap{
		"@context":   []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":       []interface{}{"VerifiableCredential", "BitstringStatusListCredential"},
		"issuer":     entriesIssuer,
		"validFrom":  now.Add(-time.Hour).Format(time.RFC3339),
		"validUntil": now.Add(time.Hour).Format(time.RFC3339),
		"credentialSubject": map[string]interface{}{
			"type":          "BitstringStatusList",
			"statusPurpose": "revocation",
			"encodedList":   "u" + encoded,
		},
	}
	sp, err := signer.NewP256Provider(priv)
	require.NoError(t, err)
	for range proofs {
		require.NoError(t, list.AddECDSAProof(sp, entriesIssuer+"#key-1", "assertionMethod"))
	}

	hits = &atomic.Int32{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]interface{}(list))
	}))
	t.Cleanup(server.Close)
	credentialstatus.SetDefaultHTTPClient(&http.Client{Timeout: 10 * time.Second})
	t.Cleanup(func() { credentialstatus.SetDefaultHTTPClient(nil) })
	return server.URL, resolver, hits
}

func revocationEntry(url, index string) map[string]interface{} {
	return map[string]interface{}{
		"type":                 "BitstringStatusListEntry",
		"statusPurpose":        "revocation",
		"statusListCredential": url,
		"statusListIndex":      index,
	}
}

// TestCheckRevocation_StatusArray_EveryEntryRead checks that each entry of a
// credentialStatus set is read: the first entry's bit is clear, the second's
// is set, and the credential is refused for the second.
func TestCheckRevocation_StatusArray_EveryEntryRead(t *testing.T) {
	url, resolver, _ := serveSignedStatusList(t, 9)
	data := CredentialData{
		"issuer":           entriesIssuer,
		"credentialStatus": []interface{}{revocationEntry(url, "3"), revocationEntry(url, "9")},
	}
	err := checkRevocation(data, resolver, false, 0)
	assert.ErrorContains(t, err, "credentialStatus[1]")
	assert.ErrorContains(t, err, "credential status is set")

	data["credentialStatus"] = []interface{}{revocationEntry(url, "3"), revocationEntry(url, "4")}
	assert.NoError(t, checkRevocation(data, resolver, false, 0))
}

// TestCheckRevocation_StatusArray_ListFetchedOnce checks that entries sharing a
// status list cost one fetch between them.
func TestCheckRevocation_StatusArray_ListFetchedOnce(t *testing.T) {
	url, resolver, hits := serveSignedStatusList(t)
	entries := make([]interface{}, 100)
	for i := range entries {
		entries[i] = revocationEntry(url, "5")
	}
	require.NoError(t, checkRevocation(CredentialData{"issuer": entriesIssuer, "credentialStatus": entries}, resolver, false, 0))
	assert.Equal(t, int32(1), hits.Load(), "status list fetches")
}

// TestCheckRevocation_StatusListProofCap checks that the credential's proof
// cap also bounds the proof set of a status list it fetches.
func TestCheckRevocation_StatusListProofCap(t *testing.T) {
	url, resolver, _ := serveStatusList(t, 2)
	data := CredentialData{"issuer": entriesIssuer, "credentialStatus": revocationEntry(url, "3")}
	assert.ErrorIs(t, checkRevocation(data, resolver, false, 1), jsonmap.ErrTooManyProofs)
	assert.NoError(t, checkRevocation(data, resolver, false, 2))
}

// TestStatusLists_ListDroppedAfterLastEntry checks that a verified list is
// released once no later entry reads it, so a credential naming many lists
// does not hold all of them at once.
func TestStatusLists_ListDroppedAfterLastEntry(t *testing.T) {
	url, resolver, hits := serveSignedStatusList(t)
	lists := &statusLists{
		client:    credentialstatus.NewClient(credentialstatus.WithResolver(resolver)),
		issuerDID: entriesIssuer,
		verified:  map[statusListKey]*credentialstatus.StatusList{},
		remaining: map[statusListKey]int{{url: url, purpose: "revocation"}: 2},
	}
	require.NoError(t, lists.check(url, "revocation", 1))
	assert.Len(t, lists.verified, 1, "kept for the second entry")
	require.NoError(t, lists.check(url, "revocation", 2))
	assert.Empty(t, lists.verified, "released after the last entry")
	assert.Equal(t, int32(1), hits.Load())
}
