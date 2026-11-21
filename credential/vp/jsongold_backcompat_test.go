package vp_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"embed"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	vmpkg "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/vp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//go:embed testdata/jsongold-fixtures/*
var vpFixtureFS embed.FS

func vpFixtureResolver(t *testing.T) vmpkg.ResolverProvider {
	t.Helper()
	data, err := vpFixtureFS.ReadFile("testdata/jsongold-fixtures/keys.json")
	require.NoError(t, err)
	var keys map[string]string
	require.NoError(t, json.Unmarshal(data, &keys))

	privBytes, err := hex.DecodeString(keys["p256_priv_hex"])
	require.NoError(t, err)

	key := new(ecdsa.PrivateKey)
	key.Curve = elliptic.P256()
	key.D = new(big.Int).SetBytes(privBytes)
	key.X, key.Y = elliptic.P256().ScalarBaseMult(privBytes)

	issuerVM, err := vmpkg.NewP256VM("did:example:fixture-issuer", "key-1", &key.PublicKey)
	require.NoError(t, err)
	holderVM, err := vmpkg.NewP256VM("did:example:fixture-holder", "key-1", &key.PublicKey)
	require.NoError(t, err)
	return vmpkg.NewStaticResolver(
		vmpkg.NewDIDDocument("did:example:fixture-issuer", issuerVM),
		vmpkg.NewDIDDocument("did:example:fixture-holder", holderVM),
	)
}

// TestBackcompat_VP20EmbeddedJSONLD_BreakingChange documents the #186 breaking
// change: a VP v2 signed on main (piprate v0.7.0) that embeds a JSON-LD VC no
// longer verifies because the fork now places the embedded VC triples in a
// named graph (correct per JSON-LD @container: @graph), changing the canonical
// N-Quads and thus the signature input.
//
// This is an expected breaking change. VPs are short-lived, so stored ones
// should be rare. The fix makes Go's output match every other conforming
// implementation, which is required for cross-SDK VP verification (#186).
func TestBackcompat_VP20EmbeddedJSONLD_BreakingChange(t *testing.T) {
	data, err := vpFixtureFS.ReadFile("testdata/jsongold-fixtures/vp20-embedded-jsonld.json")
	require.NoError(t, err)

	pres, err := vp.ParseJSONPresentation(data)
	require.NoError(t, err, "parse fixture")

	err = pres.Verify(vp.WithResolver(vpFixtureResolver(t)))

	// The VP does NOT verify because the canonical N-Quads changed.
	require.Error(t, err, "a VP v2 with an embedded VC signed by the old canonicalizer should no longer verify")
	assert.True(t, strings.Contains(err.Error(), "invalid proof"),
		"expected 'invalid proof', got: %v", err)

	// The embedded VC itself is unaffected: its proof covers only the VC
	// document, not the VP's graph structure.
}
