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

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/pilacorp/go-credential-sdk/credential/common/ecdsasd"
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

func fixtureSecpResolver(t *testing.T) vmpkg.ResolverProvider {
	t.Helper()
	data, err := fixtureFS.ReadFile("testdata/jsongold-fixtures/keys.json")
	require.NoError(t, err)
	var keys map[string]string
	require.NoError(t, json.Unmarshal(data, &keys))

	secpVM := vmpkg.NewSecp256k1VM("did:example:fixture-issuer", "key-secp", keys["secp256k1_pub_hex"])
	return vmpkg.NewStaticResolver(
		vmpkg.NewDIDDocument("did:example:fixture-issuer", secpVM),
	)
}

func fixtureSecpPub(t *testing.T) *ecdsa.PublicKey {
	t.Helper()
	data, err := fixtureFS.ReadFile("testdata/jsongold-fixtures/keys.json")
	require.NoError(t, err)
	var keys map[string]string
	require.NoError(t, json.Unmarshal(data, &keys))

	priv, err := ethcrypto.HexToECDSA(keys["secp256k1_priv_hex"])
	require.NoError(t, err)
	return &priv.PublicKey
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

// TestBackcompat_Secp256k1VCsStillVerify checks EcdsaSecp256k1Signature2019
// credentials signed on main still verify after the bump. authen-service issues
// secp256k1 credentials via signer.NewDefaultProvider, so this is a production
// signing path.
func TestBackcompat_Secp256k1VCsStillVerify(t *testing.T) {
	resolver := fixtureSecpResolver(t)

	for _, name := range []string{
		"vc11-secp256k1",
		"vc20-secp256k1",
	} {
		t.Run(name, func(t *testing.T) {
			data, err := fixtureFS.ReadFile("testdata/jsongold-fixtures/" + name + ".json")
			require.NoError(t, err)

			cred, err := vc.ParseJSONCredential(data)
			require.NoError(t, err, "parse fixture")

			err = cred.Verify(vc.WithResolver(resolver))
			assert.NoError(t, err, "verify secp256k1 fixture signed on main")
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
		"vc11-secp256k1",
		"vc20-secp256k1",
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
		"vc11-secp256k1",
		"vc20-secp256k1",
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

// TestBackcompat_JWTHashUnchanged checks that JWT credentials — which carry no
// JSON-LD canonicalization — keep the same Hash() after the bump.
func TestBackcompat_JWTHashUnchanged(t *testing.T) {
	for _, tc := range []struct {
		name      string
		tokenFile string
		hashFile  string
	}{
		{"vc11-jwt", "vc11-jwt.token", "vc11-jwt.hash"},
		{"vc20-jose", "vc20-jose.token", "vc20-jose.hash"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tokenBytes, err := fixtureFS.ReadFile("testdata/jsongold-fixtures/" + tc.tokenFile)
			require.NoError(t, err)
			token := strings.TrimSpace(string(tokenBytes))

			cred, err := vc.ParseCredential([]byte(token))
			require.NoError(t, err, "parse JWT fixture")

			got, err := cred.Hash()
			require.NoError(t, err)

			wantBytes, err := fixtureFS.ReadFile("testdata/jsongold-fixtures/" + tc.hashFile)
			require.NoError(t, err)
			want := strings.TrimSpace(string(wantBytes))

			assert.Equal(t, want, got, "JWT Hash() changed after the json-gold bump")
		})
	}
}

// TestBackcompat_EcdsaSD2023BaseVerifies checks that an ecdsa-sd-2023 base
// proof signed on main still verifies. The ecdsa-sd path uses
// standardizeForCanonicalization (the modern canonicalize path), so this is
// the selective-disclosure production path.
func TestBackcompat_EcdsaSD2023BaseVerifies(t *testing.T) {
	data, err := fixtureFS.ReadFile("testdata/jsongold-fixtures/vc20-ecdsasd-base.json")
	require.NoError(t, err)

	var cred map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &cred))

	proof, ok := cred["proof"].(map[string]interface{})
	require.True(t, ok, "proof must be an object")
	proofValue, ok := proof["proofValue"].(string)
	require.True(t, ok, "proofValue must be a string")

	_, pub := fixtureKeys(t)

	doc := make(map[string]interface{})
	for k, v := range cred {
		if k != "proof" {
			doc[k] = v
		}
	}

	proofConfig := map[string]interface{}{
		"@context":           "https://w3id.org/security/data-integrity/v2",
		"type":               proof["type"],
		"cryptosuite":        proof["cryptosuite"],
		"created":            proof["created"],
		"verificationMethod": proof["verificationMethod"],
		"proofPurpose":       proof["proofPurpose"],
	}

	err = ecdsasd.VerifyProof(doc, proofConfig, proofValue, pub)
	assert.NoError(t, err, "ecdsa-sd-2023 base proof signed on main should still verify")
}

// TestBackcompat_EcdsaSD2023DerivedVerifies checks that an ecdsa-sd-2023
// derived (selective disclosure) proof signed on main still verifies.
func TestBackcompat_EcdsaSD2023DerivedVerifies(t *testing.T) {
	data, err := fixtureFS.ReadFile("testdata/jsongold-fixtures/vc20-ecdsasd-derived.json")
	require.NoError(t, err)

	var cred map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &cred))

	proof, ok := cred["proof"].(map[string]interface{})
	require.True(t, ok, "proof must be an object")
	proofValue, ok := proof["proofValue"].(string)
	require.True(t, ok, "proofValue must be a string")

	_, pub := fixtureKeys(t)

	doc := make(map[string]interface{})
	for k, v := range cred {
		if k != "proof" {
			doc[k] = v
		}
	}

	proofConfig := map[string]interface{}{
		"@context":           "https://w3id.org/security/data-integrity/v2",
		"type":               proof["type"],
		"cryptosuite":        proof["cryptosuite"],
		"created":            proof["created"],
		"verificationMethod": proof["verificationMethod"],
		"proofPurpose":       proof["proofPurpose"],
	}

	err = ecdsasd.VerifyProof(doc, proofConfig, proofValue, pub)
	assert.NoError(t, err, "ecdsa-sd-2023 derived proof signed on main should still verify")
}
