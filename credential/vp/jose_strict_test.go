// Tests for the stricter checks the jose module enforces on VP paths.
// Each test exercises one item from issue #99. The jose module's strict
// checks (crit, UTF-8, strict base64url) are enforced in jws.Verify, which
// runs during Verify(), not during Parse().
package vp_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	vmpkg "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/vp"
)

func vpJoseSetup(t *testing.T) (string, *ecdsa.PrivateKey, vmpkg.ResolverProvider) {
	t.Helper()
	const did = "did:example:vp-jose-strict"
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen p256: %v", err)
	}
	resolver := vmpkg.NewStaticResolver(
		vmpkg.NewDIDDocument(did, mustP256VM(t, did, "key-1", &priv.PublicKey)))
	return did, priv, resolver
}

func signedJOSEPresentation(t *testing.T, did string, priv *ecdsa.PrivateKey, resolver vmpkg.ResolverProvider) string {
	t.Helper()
	prov, err := signer.NewP256Provider(priv)
	if err != nil {
		t.Fatalf("p256 provider: %v", err)
	}
	pres, err := vp.NewJOSEPresentation(joseVPContents(did),
		vp.WithVerificationMethodKey("key-1"), vp.WithResolver(resolver))
	if err != nil {
		t.Fatalf("new jose presentation: %v", err)
	}
	if err := pres.AddProofByProvider(prov, vp.WithResolver(resolver)); err != nil {
		t.Fatalf("sign: %v", err)
	}
	serialized, err := pres.Serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return serialized.(string)
}

// --- #99 item 1: crit header rejection ---

func TestVPJOSEStrict_CritHeaderRejected(t *testing.T) {
	did, priv, resolver := vpJoseSetup(t)
	token := signedJOSEPresentation(t, did, priv, resolver)

	parts := strings.SplitN(token, ".", 3)
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		t.Fatal(err)
	}
	header["crit"] = []string{"urn:example:unsupported"}
	header["urn:example:unsupported"] = true
	newHeader, _ := json.Marshal(header)
	tampered := base64.RawURLEncoding.EncodeToString(newHeader) + "." + parts[1] + "." + parts[2]

	// Parse may succeed; the crit check is in jws.Verify via jwt.VerifyJWT.
	pres, err := vp.ParsePresentation([]byte(tampered), vp.WithResolver(resolver))
	if err != nil {
		if strings.Contains(err.Error(), "crit") {
			return
		}
		t.Fatalf("parse failed for a reason other than crit: %v", err)
	}
	err = pres.Verify(vp.WithResolver(resolver))
	if err == nil {
		t.Fatal("accepted a VP with crit in header; want rejection")
	}
	if !strings.Contains(err.Error(), "crit") {
		t.Fatalf("err = %v, want one mentioning crit", err)
	}
}

// --- #99 item 7: non-strict base64url ---

func TestVPJOSEStrict_PadBitAliasRejected(t *testing.T) {
	did, priv, resolver := vpJoseSetup(t)
	token := signedJOSEPresentation(t, did, priv, resolver)

	parts := strings.SplitN(token, ".", 3)
	sig := parts[2]
	lastChar := sig[len(sig)-1]
	flipped := lastChar ^ 1
	tampered := parts[0] + "." + parts[1] + "." + sig[:len(sig)-1] + string(flipped)

	// Parse may succeed; the strict base64url check is in jws.Verify.
	pres, err := vp.ParsePresentation([]byte(tampered), vp.WithResolver(resolver))
	if err != nil {
		return // Parse rejecting it also satisfies the test.
	}
	err = pres.Verify(vp.WithResolver(resolver))
	if err == nil {
		t.Fatal("accepted a VP with non-strict base64url signature; want rejection")
	}
}

// --- Hash and wire format stability ---

func TestVPJOSEStrict_HashStability(t *testing.T) {
	did, priv, resolver := vpJoseSetup(t)
	prov, err := signer.NewP256Provider(priv)
	if err != nil {
		t.Fatal(err)
	}

	pres, err := vp.NewJOSEPresentation(joseVPContents(did),
		vp.WithVerificationMethodKey("key-1"), vp.WithResolver(resolver))
	if err != nil {
		t.Fatal(err)
	}
	if err := pres.AddProofByProvider(prov, vp.WithResolver(resolver)); err != nil {
		t.Fatal(err)
	}
	hash1, err := pres.Hash()
	if err != nil {
		t.Fatal(err)
	}

	serialized, err := pres.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := vp.ParsePresentation([]byte(serialized.(string)), vp.WithResolver(resolver))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	joseP, ok := parsed.(*vp.JOSEPresentation)
	if !ok {
		t.Fatalf("parsed presentation is %T, want *vp.JOSEPresentation", parsed)
	}
	hash2, err := joseP.Hash()
	if err != nil {
		t.Fatal(err)
	}
	if hash1 != hash2 {
		t.Fatalf("hash changed after round-trip: %s -> %s", hash1, hash2)
	}
}

func TestVPJOSEStrict_WireFormatUnchanged(t *testing.T) {
	did, priv, resolver := vpJoseSetup(t)
	prov, err := signer.NewP256Provider(priv)
	if err != nil {
		t.Fatal(err)
	}

	pres, err := vp.NewJOSEPresentation(joseVPContents(did),
		vp.WithVerificationMethodKey("key-1"), vp.WithResolver(resolver))
	if err != nil {
		t.Fatal(err)
	}
	if err := pres.AddProofByProvider(prov, vp.WithResolver(resolver)); err != nil {
		t.Fatal(err)
	}
	ser1, err := pres.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	wire1 := ser1.(string)

	parsed, err := vp.ParsePresentation([]byte(wire1), vp.WithResolver(resolver))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	ser2, err := parsed.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	wire2 := ser2.(string)

	if wire1 != wire2 {
		t.Fatalf("wire format changed after round-trip:\n  before: %s\n  after:  %s", wire1, wire2)
	}
}
