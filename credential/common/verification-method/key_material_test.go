package verificationmethod

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

// --- helpers ---

// jwkFor builds an EC JWK with coordinates left-padded to size (RFC 7518).
func jwkFor(crv string, pub *ecdsa.PublicKey, size int) *JWK {
	xb := make([]byte, size)
	yb := make([]byte, size)
	pub.X.FillBytes(xb)
	pub.Y.FillBytes(yb)
	return &JWK{
		Kty: "EC",
		Crv: crv,
		X:   base64.RawURLEncoding.EncodeToString(xb),
		Y:   base64.RawURLEncoding.EncodeToString(yb),
	}
}

func genKey(t *testing.T, crv string) (*ecdsa.PublicKey, int) {
	t.Helper()
	switch crv {
	case "secp256k1":
		priv, err := crypto.GenerateKey()
		if err != nil {
			t.Fatalf("generate secp256k1: %v", err)
		}
		return &priv.PublicKey, 32
	case "P-256":
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate P-256: %v", err)
		}
		return &priv.PublicKey, 32
	case "P-384":
		priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			t.Fatalf("generate P-384: %v", err)
		}
		return &priv.PublicKey, 48
	}
	t.Fatalf("unknown curve %s", crv)
	return nil, 0
}

func newSecp256k1Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	priv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate secp256k1 key: %v", err)
	}
	return priv
}

func mustEncode(t *testing.T, pub *ecdsa.PublicKey) string {
	t.Helper()
	s, err := EncodePubMultibase(pub)
	if err != nil {
		t.Fatalf("EncodePubMultibase: %v", err)
	}
	return s
}

// --- JWK ---

// All three curves round-trip, as SEC1 uncompressed sized to the field.
func TestECPubFromJWK_AllCurves(t *testing.T) {
	for _, crv := range []string{"secp256k1", "P-256", "P-384"} {
		t.Run(crv, func(t *testing.T) {
			pub, size := genKey(t, crv)

			got, err := ECPubFromJWK(jwkFor(crv, pub, size))
			if err != nil {
				t.Fatalf("ECPubFromJWK: %v", err)
			}

			raw := marshalUncompressed(got)
			if want := 1 + 2*size; len(raw) != want {
				t.Fatalf("len = %d bytes, want %d", len(raw), want)
			}
			if raw[0] != 0x04 {
				t.Errorf("first byte = %#x, want 0x04 (uncompressed)", raw[0])
			}
			if x := new(big.Int).SetBytes(raw[1 : 1+size]); x.Cmp(pub.X) != 0 {
				t.Errorf("X coordinate did not round-trip")
			}
			if y := new(big.Int).SetBytes(raw[1+size:]); y.Cmp(pub.Y) != 0 {
				t.Errorf("Y coordinate did not round-trip")
			}
		})
	}
}

// The old version hard-coded secp256k1; a P-256 JWK must keep its curve.
func TestECPubFromJWK_KeepsCurve(t *testing.T) {
	pub, size := genKey(t, "P-256")
	got, err := ECPubFromJWK(jwkFor("P-256", pub, size))
	if err != nil {
		t.Fatalf("ECPubFromJWK: %v", err)
	}
	if got.Curve != elliptic.P256() {
		t.Errorf("Curve = %v, want P-256", got.Curve.Params().Name)
	}
}

func TestECPubFromJWK_RejectsOffCurvePoint(t *testing.T) {
	pub, size := genKey(t, "P-256")
	bad := &ecdsa.PublicKey{
		Curve: pub.Curve,
		X:     pub.X,
		Y:     new(big.Int).Add(pub.Y, big.NewInt(1)), // off-curve
	}
	if _, err := ECPubFromJWK(jwkFor("P-256", bad, size)); err == nil {
		t.Fatal("ECPubFromJWK accepted an off-curve point, want error")
	}
}

func TestECPubFromJWK_RejectsBadInput(t *testing.T) {
	pub, size := genKey(t, "P-256")

	t.Run("unsupported curve", func(t *testing.T) {
		jwk := jwkFor("P-521", pub, size)
		if _, err := ECPubFromJWK(jwk); err == nil {
			t.Fatal("accepted crv=P-521, want error")
		}
	})

	t.Run("unsupported kty", func(t *testing.T) {
		jwk := jwkFor("P-256", pub, size)
		jwk.Kty = "OKP"
		if _, err := ECPubFromJWK(jwk); err == nil {
			t.Fatal("accepted kty=OKP, want error")
		}
	})

	t.Run("oversized coordinate", func(t *testing.T) {
		jwk := jwkFor("P-256", pub, 48) // oversized for a 32-byte curve
		if _, err := ECPubFromJWK(jwk); err == nil {
			t.Fatal("accepted a 48-byte coordinate on P-256, want error")
		}
	})

	t.Run("nil", func(t *testing.T) {
		if _, err := ECPubFromJWK(nil); err == nil {
			t.Fatal("accepted a nil jwk, want error")
		}
	})
}

// Some DID documents strip leading zeros; those must still parse.
func TestECPubFromJWK_AcceptsShortCoordinate(t *testing.T) {
	var pub *ecdsa.PublicKey
	for i := 0; i < 3000 && pub == nil; i++ {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate P-256: %v", err)
		}
		if len(priv.PublicKey.X.Bytes()) < 32 { // X has a leading zero byte
			pub = &priv.PublicKey
		}
	}
	if pub == nil {
		t.Fatal("no P-256 key with a short X coordinate found in 3000 tries")
	}

	jwk := &JWK{
		Kty: "EC",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(pub.X.Bytes()),
		Y:   base64.RawURLEncoding.EncodeToString(pub.Y.Bytes()),
	}
	got, err := ECPubFromJWK(jwk)
	if err != nil {
		t.Fatalf("ECPubFromJWK on a short coordinate: %v", err)
	}
	if got.X.Cmp(pub.X) != 0 || got.Y.Cmp(pub.Y) != 0 {
		t.Error("short coordinate did not round-trip")
	}
}

func TestP256PubKeyFromJWK_RejectsOtherCurves(t *testing.T) {
	pub, size := genKey(t, "P-384")
	if _, err := P256PubKeyFromJWK(jwkFor("P-384", pub, size)); err == nil {
		t.Fatal("P256PubKeyFromJWK accepted a P-384 JWK, want error")
	}
}

// --- Multibase ---

// Multibase carries its curve in the multicodec prefix.
func TestECPubFromMultibase_NISTCurves(t *testing.T) {
	for _, crv := range []string{"P-256", "P-384"} {
		t.Run(crv, func(t *testing.T) {
			pub, size := genKey(t, crv)

			got, err := ECPubFromMultibase(mustEncode(t, pub))
			if err != nil {
				t.Fatalf("ECPubFromMultibase: %v", err)
			}
			if len(marshalUncompressed(got)) != 1+2*size {
				t.Fatalf("decoded on the wrong curve: %s", got.Curve.Params().Name)
			}
			if got.X.Cmp(pub.X) != 0 || got.Y.Cmp(pub.Y) != 0 {
				t.Error("key did not round-trip")
			}
		})
	}
}

// A prefix naming a curve this SDK does not implement is refused. Ed25519
// (0xed01) is not an ECDSA curve at all; P-521 (0x1202) is ECDSA but unwired.
//
// secp256k1 (0xe701) used to be on this list. It is accepted now — see
// TestECPubFromMultibase_Secp256k1 — because publicKeyHex is not a property DID
// Core defines, so a conforming resolver reads no key from it (#91).
func TestECPubFromMultibase_RejectsUnsupportedPrefix(t *testing.T) {
	for name, prefix := range map[string][]byte{
		"ed25519": {0xed, 0x01},
		"p521":    {0x82, 0x24},
	} {
		t.Run(name, func(t *testing.T) {
			mk := EncodeMultibaseKey(append(prefix, make([]byte, 33)...))
			if _, err := ECPubFromMultibase(mk); err == nil {
				t.Fatalf("ECPubFromMultibase accepted a %s Multikey, want error", name)
			}
		})
	}
}

// A secp256k1 Multikey round-trips through the encoder and back to the same
// point.
//
// Decoding it does not go through elliptic.UnmarshalCompressed: that function
// decompresses with the NIST polynomial y² = x³ - 3x + b, and secp256k1 is
// y² = x³ + 7. Handed a genuine secp256k1 point it returns nil — so the pair of
// assertions below is the whole point of the test, and a fixture of 33 zero
// bytes would have passed against either implementation.
func TestECPubFromMultibase_Secp256k1(t *testing.T) {
	priv := newSecp256k1Key(t)
	pub := &priv.PublicKey

	mk, err := EncodePubMultibase(pub)
	if err != nil {
		t.Fatalf("EncodePubMultibase: %v", err)
	}
	raw, err := DecodeMultibaseKey(mk)
	if err != nil {
		t.Fatalf("DecodeMultibaseKey: %v", err)
	}
	if want := []byte{0xe7, 0x01}; !bytes.HasPrefix(raw, want) {
		t.Errorf("multicodec prefix = %#x, want %#x (secp256k1-pub)", raw[:2], want)
	}
	if len(raw) != 2+33 {
		t.Errorf("multikey is %d bytes, want 35 (prefix + compressed point)", len(raw))
	}

	got, err := ECPubFromMultibase(mk)
	if err != nil {
		t.Fatalf("ECPubFromMultibase: %v", err)
	}
	if got.X.Cmp(pub.X) != 0 || got.Y.Cmp(pub.Y) != 0 {
		t.Error("key did not round-trip")
	}
	if !CurveIsSecp256k1(got.Curve) {
		t.Errorf("decoded on the wrong curve: %s", curveName(got.Curve))
	}
}

// CurveIsSecp256k1 compares by the curve's order, because elliptic.Curve is an
// interface: == compares the dynamic type and pointer, and go-ethereum's
// BitCurve is a different object from btcec's KoblitzCurve. A copy of the
// params stands in for the other library here — the same curve, a different
// object.
func TestCurveIsSecp256k1_ComparesByOrderNotByValue(t *testing.T) {
	// A *elliptic.CurveParams carrying secp256k1's parameters: the same curve as
	// go-ethereum's S256(), and not the same object — it is not even the same
	// Go type, so == could never match it.
	same := *crypto.S256().Params()
	other := &same

	if !CurveIsSecp256k1(other) {
		t.Error("a second object describing secp256k1 was not recognized")
	}
	if CurveIsSecp256k1(elliptic.P256()) {
		t.Error("P-256 was recognized as secp256k1")
	}
	if CurveIsSecp256k1(nil) {
		t.Error("nil was recognized as secp256k1")
	}
}

// A secp256k1 key published as a Multikey must read back, and must be reported
// as secp256k1 rather than P-256: VMKeyKind asks VMIsSecp256k1 first, and
// signing picks the cryptosuite from the answer.
func TestECPubFromVM_Secp256k1Multikey(t *testing.T) {
	priv := newSecp256k1Key(t)
	pub := &priv.PublicKey

	vm, err := NewSecp256k1MultikeyVM("did:example:multikey", "key-1", pub)
	if err != nil {
		t.Fatalf("NewSecp256k1MultikeyVM: %v", err)
	}
	if vm.Type != "Multikey" {
		t.Errorf("type = %q, want Multikey", vm.Type)
	}
	if vm.PublicKeyHex != "" {
		t.Errorf("publicKeyHex = %q, want it unset", vm.PublicKeyHex)
	}

	got, err := ECPubFromVM(&vm)
	if err != nil {
		t.Fatalf("ECPubFromVM: %v", err)
	}
	if got.X.Cmp(pub.X) != 0 || got.Y.Cmp(pub.Y) != 0 {
		t.Error("key did not round-trip through the verification method")
	}
	if !VMIsSecp256k1(&vm) {
		t.Error("VMIsSecp256k1 did not recognize a secp256k1 Multikey")
	}
	if VMIsP256(&vm) {
		t.Error("VMIsP256 claimed a secp256k1 Multikey")
	}
	kind, ok := VMKeyKind(&vm)
	if !ok || kind != KeySecp256k1 {
		t.Errorf("VMKeyKind = (%v, %v), want (secp256k1, true)", kind, ok)
	}
}

// The other direction of the same rule: a P-256 Multikey must not be claimed by
// VMIsSecp256k1, which is asked first.
func TestVMKeyKind_P256MultikeyStillReadsAsP256(t *testing.T) {
	pub, _ := genKey(t, "P-256")

	vm, err := NewP256MultikeyVM("did:example:multikey", "key-1", pub)
	if err != nil {
		t.Fatalf("NewP256MultikeyVM: %v", err)
	}
	if VMIsSecp256k1(&vm) {
		t.Error("VMIsSecp256k1 claimed a P-256 Multikey")
	}
	kind, ok := VMKeyKind(&vm)
	if !ok || kind != KeyP256 {
		t.Errorf("VMKeyKind = (%v, %v), want (P-256, true)", kind, ok)
	}
}

func TestNewSecp256k1MultikeyVM_RefusesOtherCurves(t *testing.T) {
	p256, _ := genKey(t, "P-256")

	if _, err := NewSecp256k1MultikeyVM("did:example:x", "key-1", p256); err == nil {
		t.Error("a P-256 key was accepted as a secp256k1 Multikey")
	}
	if _, err := NewSecp256k1MultikeyVM("did:example:x", "key-1", nil); err == nil {
		t.Error("a nil key was accepted")
	}
}

// The same key in both representations must give the same key, otherwise a
// credential would verify against a DID document published one way and fail
// against the other during the migration off publicKeyHex.
func TestECPubFromVM_HexAndMultikeyAgree(t *testing.T) {
	priv := newSecp256k1Key(t)
	pub := &priv.PublicKey

	hexVM := NewSecp256k1VM("did:example:x", "key-1", //nolint:staticcheck // the deprecated form is what this compares against
		hex.EncodeToString(crypto.FromECDSAPub(pub)))
	mkVM, err := NewSecp256k1MultikeyVM("did:example:x", "key-2", pub)
	if err != nil {
		t.Fatalf("NewSecp256k1MultikeyVM: %v", err)
	}

	fromHex, err := ECPubFromVM(&hexVM)
	if err != nil {
		t.Fatalf("ECPubFromVM(hex): %v", err)
	}
	fromMK, err := ECPubFromVM(&mkVM)
	if err != nil {
		t.Fatalf("ECPubFromVM(multikey): %v", err)
	}
	if fromHex.X.Cmp(fromMK.X) != 0 || fromHex.Y.Cmp(fromMK.Y) != 0 {
		t.Error("publicKeyHex and publicKeyMultibase decoded to different keys")
	}
}

// --- ECPubFromVM ---

// Both secp256k1 encodings of one key must yield the same key, otherwise a
// verifier would accept a credential under one and reject it under the other.
func TestECPubFromVM_HexAndJWK(t *testing.T) {
	priv := newSecp256k1Key(t)
	pub := &priv.PublicKey

	xb := make([]byte, 32)
	yb := make([]byte, 32)
	pub.X.FillBytes(xb)
	pub.Y.FillBytes(yb)

	cases := []struct {
		name string
		vm   VerificationMethodEntry
	}{
		{
			name: "publicKeyHex",
			vm:   VerificationMethodEntry{ID: "did:example:1#k", PublicKeyHex: "0x" + hex.EncodeToString(marshalUncompressed(pub))},
		},
		{
			name: "publicKeyJwk",
			vm: VerificationMethodEntry{ID: "did:example:1#k", PublicKeyJwk: &JWK{
				Kty: "EC",
				Crv: "secp256k1",
				X:   base64.RawURLEncoding.EncodeToString(xb),
				Y:   base64.RawURLEncoding.EncodeToString(yb),
			}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ECPubFromVM(&tc.vm)
			if err != nil {
				t.Fatalf("ECPubFromVM: %v", err)
			}
			if got.X.Cmp(pub.X) != 0 || got.Y.Cmp(pub.Y) != 0 {
				t.Error("key did not round-trip")
			}
		})
	}
}

// did/helper.go publishes publicKeyHex compressed, so that shape must parse.
func TestECPubFromVM_CompressedHex(t *testing.T) {
	priv := newSecp256k1Key(t)
	pub := &priv.PublicKey
	vm := VerificationMethodEntry{
		ID:           "did:example:1#k",
		PublicKeyHex: hex.EncodeToString(crypto.CompressPubkey(pub)),
	}

	got, err := ECPubFromVM(&vm)
	if err != nil {
		t.Fatalf("ECPubFromVM: %v", err)
	}
	if got.X.Cmp(pub.X) != 0 || got.Y.Cmp(pub.Y) != 0 {
		t.Error("compressed hex did not round-trip")
	}
}

// A P-256 JWK passes through, on its own curve.
func TestECPubFromVM_P256JWK(t *testing.T) {
	pub, size := genKey(t, "P-256")
	vm := VerificationMethodEntry{ID: "did:example:1#k", PublicKeyJwk: jwkFor("P-256", pub, size)}

	got, err := ECPubFromVM(&vm)
	if err != nil {
		t.Fatalf("ECPubFromVM: %v", err)
	}
	if got.Curve != elliptic.P256() || got.X.Cmp(pub.X) != 0 || got.Y.Cmp(pub.Y) != 0 {
		t.Error("key did not round-trip on P-256")
	}
}

// A P-256 Multikey decodes on its own curve, not as secp256k1.
func TestECPubFromVM_P256Multikey(t *testing.T) {
	p256Priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-256 key: %v", err)
	}
	pub := &p256Priv.PublicKey
	vm := VerificationMethodEntry{
		ID:                 "did:example:1#k",
		PublicKeyMultibase: mustEncode(t, pub),
	}

	got, err := ECPubFromVM(&vm)
	if err != nil {
		t.Fatalf("ECPubFromVM: %v", err)
	}
	if got.Curve != elliptic.P256() || got.X.Cmp(pub.X) != 0 || got.Y.Cmp(pub.Y) != 0 {
		t.Error("key did not round-trip on P-256")
	}
}

// A P-384 Multikey keeps its curve through ECPubFromVM.
func TestECPubFromVM_P384Multikey(t *testing.T) {
	pub, _ := genKey(t, "P-384")
	vm := VerificationMethodEntry{ID: "did:example:1#k", PublicKeyMultibase: mustEncode(t, pub)}

	got, err := ECPubFromVM(&vm)
	if err != nil {
		t.Fatalf("ECPubFromVM: %v", err)
	}
	if got.Curve != elliptic.P384() {
		t.Errorf("Curve = %s, want P-384", got.Curve.Params().Name)
	}
}

// NewP256MultikeyVM publishes the key in the W3C Multikey format, and the SDK
// still reads its kind from the key material rather than the type string.
func TestNewP256MultikeyVM(t *testing.T) {
	pub, _ := genKey(t, "P-256")

	vm, err := NewP256MultikeyVM("did:example:1", "key-1", pub)
	if err != nil {
		t.Fatalf("NewP256MultikeyVM: %v", err)
	}
	if vm.ID != "did:example:1#key-1" || vm.Type != "Multikey" {
		t.Errorf("vm = {%s, %s}, want {did:example:1#key-1, Multikey}", vm.ID, vm.Type)
	}
	if vm.PublicKeyMultibase != mustEncode(t, pub) {
		t.Error("publicKeyMultibase does not match the key")
	}
	if kind, ok := VMKeyKind(&vm); !ok || kind != KeyP256 {
		t.Errorf("VMKeyKind = %v (ok=%v), want P-256", kind, ok)
	}

	// The name promises P-256, so another curve must be refused rather than
	// published under a mismatched label.
	other, _ := genKey(t, "P-384")
	if _, err := NewP256MultikeyVM("did:example:1", "key-1", other); err == nil {
		t.Error("NewP256MultikeyVM accepted a P-384 key")
	}
}

func TestECPubFromVM_NoKeyMaterial(t *testing.T) {
	vm := VerificationMethodEntry{ID: "did:example:1#k"}
	if _, err := ECPubFromVM(&vm); err == nil {
		t.Fatal("ECPubFromVM on an empty VM returned no error")
	}
}
