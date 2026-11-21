package vc_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"embed"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/pilacorp/go-credential-sdk/credential/common/processor"
	vmpkg "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//go:embed testdata/jsongold-fixtures/*
var fixtureFS embed.FS

// fixtureKeys returns the key material used by the fixtures.
func fixtureKeys(t *testing.T) (priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey) {
	t.Helper()
	data, err := fixtureFS.ReadFile("testdata/jsongold-fixtures/keys.json")
	require.NoError(t, err)
	var keys map[string]string
	require.NoError(t, json.Unmarshal(data, &keys))

	privBytes, err := hex.DecodeString(keys["p256_priv_hex"])
	require.NoError(t, err)

	key := new(ecdsa.PrivateKey)
	key.Curve = elliptic.P256()
	key.D = new(big.Int).SetBytes(privBytes)
	key.X, key.Y = elliptic.P256().ScalarBaseMult(privBytes)
	return key, &key.PublicKey
}

func fixtureResolver(t *testing.T) vmpkg.ResolverProvider {
	t.Helper()
	_, pub := fixtureKeys(t)
	issuerVM, err := vmpkg.NewP256VM("did:example:fixture-issuer", "key-1", pub)
	require.NoError(t, err)
	holderVM, err := vmpkg.NewP256VM("did:example:fixture-holder", "key-1", pub)
	require.NoError(t, err)
	return vmpkg.NewStaticResolver(
		vmpkg.NewDIDDocument("did:example:fixture-issuer", issuerVM),
		vmpkg.NewDIDDocument("did:example:fixture-holder", holderVM),
	)
}

// TestBackcompat_VCsSignedOnMainStillVerify loads credentials signed on the
// main branch (piprate/json-gold v0.7.0) and verifies they still pass with the
// pilacorp fork. These are plain VCs (no VP graph structure), so the #186
// @graph container change does not affect them.
func TestBackcompat_VCsSignedOnMainStillVerify(t *testing.T) {
	resolver := fixtureResolver(t)

	for _, name := range []string{
		"vc11-ecdsa-rdfc-2019",
		"vc20-ecdsa-rdfc-2019",
		"vc20-with-status",
	} {
		t.Run(name, func(t *testing.T) {
			data, err := fixtureFS.ReadFile("testdata/jsongold-fixtures/" + name + ".json")
			require.NoError(t, err)

			cred, err := vc.ParseJSONCredential(data)
			require.NoError(t, err, "parse fixture")

			err = cred.Verify(vc.WithResolver(resolver))
			assert.NoError(t, err, "verify fixture — a VC signed on main must still verify after the json-gold bump")
		})
	}
}

// TestBackcompat_VCHashesUnchanged checks that the Hash() of each VC fixture
// matches the hash computed on main. If a hash changes, the credential's
// canonical form changed, which means already-issued credentials would stop
// matching their on-chain anchors.
func TestBackcompat_VCHashesUnchanged(t *testing.T) {
	for _, name := range []string{
		"vc11-ecdsa-rdfc-2019",
		"vc20-ecdsa-rdfc-2019",
		"vc20-with-status",
	} {
		t.Run(name, func(t *testing.T) {
			data, err := fixtureFS.ReadFile("testdata/jsongold-fixtures/" + name + ".json")
			require.NoError(t, err)

			cred, err := vc.ParseJSONCredential(data)
			require.NoError(t, err)

			got, err := cred.Hash()
			require.NoError(t, err)

			wantBytes, err := fixtureFS.ReadFile("testdata/jsongold-fixtures/" + name + ".hash")
			require.NoError(t, err)
			want := strings.TrimSpace(string(wantBytes))

			assert.Equal(t, want, got, "Hash() changed — the canonical form of this VC is different after the json-gold bump")
		})
	}
}

// TestBackcompat_VCCanonicalNQuadsUnchanged checks that the canonical N-Quads
// of each VC fixture body (without proof) are identical to what main produced.
func TestBackcompat_VCCanonicalNQuadsUnchanged(t *testing.T) {
	for _, name := range []string{
		"vc11-ecdsa-rdfc-2019",
		"vc20-ecdsa-rdfc-2019",
		"vc20-with-status",
	} {
		t.Run(name, func(t *testing.T) {
			data, err := fixtureFS.ReadFile("testdata/jsongold-fixtures/" + name + ".json")
			require.NoError(t, err)

			var doc map[string]interface{}
			require.NoError(t, json.Unmarshal(data, &doc))
			delete(doc, "proof")

			got, err := processor.Canonicalize(doc)
			require.NoError(t, err)

			wantBytes, err := fixtureFS.ReadFile("testdata/jsongold-fixtures/" + name + ".nq")
			require.NoError(t, err)

			assert.Equal(t, string(wantBytes), string(got),
				"canonical N-Quads changed — the json-gold bump altered this VC's canonical form")
		})
	}
}
