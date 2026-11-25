package did

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"maps"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

// Hardhat test account #1: its compressed key and the JWK of the same point.
const (
	jwkTestDID    = "did:nda:testnet:0x70997970c51812dc3a010c7d01b50e0d17dc79c8"
	jwkTestKeyHex = "02ba5734d8f7091719471e7f7ed6b9df170dc70cc661ca05e688601ad984f068b0"
	jwkTestX      = "ulc02PcJFxlHHn9-1rnfFw3HDMZhygXmiGAa2YTwaLA"
	jwkTestY      = "1nNR5fBgcwkkmTNqsIOe-KUhr9M05TgHIF-i8I7sdPQ"
)

func sampleJWK() map[string]any {
	return map[string]any{"kty": "EC", "crv": "secp256k1", "x": jwkTestX, "y": jwkTestY}
}

func jwkVM(id string, jwk map[string]any) VerificationMethod {
	return VerificationMethod{Id: id, Type: jsonWebKeyVMType, Controller: jwkTestDID, PublicKeyJwk: jwk}
}

func with(jwk map[string]any, k string, v any) map[string]any {
	out := maps.Clone(jwk)
	out[k] = v

	return out
}

func without(jwk map[string]any, k string) map[string]any {
	out := maps.Clone(jwk)
	delete(out, k)

	return out
}

// oneDocWithKey1 is the sample DID with only its secp256k1 key at #key-1.
func oneDocWithKey1() *DIDDocument {
	return GenerateDIDDocument(jwkTestKeyHex, jwkTestDID, "", jwkTestDID, DIDTypePeople, nil)
}

func TestVMTypeFor_AcceptsPublicJWK(t *testing.T) {
	got, err := vmTypeFor(jwkVM(jwkTestDID+"#key-3", sampleJWK()))
	if err != nil {
		t.Fatalf("vmTypeFor: %v", err)
	}
	if got != jsonWebKeyVMType {
		t.Fatalf("type = %q, want %q", got, jsonWebKeyVMType)
	}

	p256 := mustP256JWK(t)
	if got, err := vmTypeFor(jwkVM(jwkTestDID+"#key-4", p256)); err != nil || got != jsonWebKeyVMType {
		t.Fatalf("P-256 JWK: type %q, err %v", got, err)
	}
}

func TestVMTypeFor_RejectsMalformedJWK(t *testing.T) {
	flipped := []byte(jwkTestX)
	flipped[5] ^= 1

	cases := map[string]struct {
		jwk  map[string]any
		want string
	}{
		"private key":        {with(sampleJWK(), "d", "AAAA"), "private key"},
		"kid":                {with(sampleJWK(), "kid", "x"), "exactly kty, crv, x, y"},
		"alg":                {with(sampleJWK(), "alg", "ES256K"), "exactly kty, crv, x, y"},
		"missing y":          {without(sampleJWK(), "y"), "exactly kty, crv, x, y"},
		"kty RSA":            {with(sampleJWK(), "kty", "RSA"), "kty"},
		"crv P-384":          {with(sampleJWK(), "crv", "P-384"), "crv"},
		"x not a string":     {with(sampleJWK(), "x", 42), "x"},
		"x padded":           {with(sampleJWK(), "x", jwkTestX+"="), "x"},
		"x standard base64":  {with(sampleJWK(), "x", strings.ReplaceAll(jwkTestX, "-", "+")), "x"},
		"x 31 bytes":         {with(sampleJWK(), "x", base64.RawURLEncoding.EncodeToString(make([]byte, 31))), "x"},
		"point off curve":    {with(sampleJWK(), "x", string(flipped)), "curve"},
		"secp point as P256": {with(sampleJWK(), "crv", "P-256"), "curve"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := vmTypeFor(jwkVM(jwkTestDID+"#key-3", tc.jwk))
			if err == nil {
				t.Fatalf("expected an error for %s", name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

func TestVMTypeFor_RejectsJWKWithOtherKeyMaterial(t *testing.T) {
	vm := jwkVM(jwkTestDID+"#key-3", sampleJWK())
	vm.PublicKeyHex = jwkTestKeyHex

	_, err := vmTypeFor(vm)
	if err == nil || !strings.Contains(err.Error(), "not both") {
		t.Fatalf("want a 'not both' error, got %v", err)
	}
}

// One key may sit at #key-1 as hex and at #key-3 as JWK, but not twice as JWK.
func TestAddVerificationMethod_JWKBesideHexOnce(t *testing.T) {
	doc := oneDocWithKey1()
	if doc == nil {
		t.Fatal("GenerateDIDDocument returned nil")
	}

	id, err := doc.AddVerificationMethod(VerificationMethod{Id: "#key-3", PublicKeyJwk: sampleJWK()}, nil)
	if err != nil {
		t.Fatalf("add JWK beside the hex key: %v", err)
	}
	if id != jwkTestDID+"#key-3" {
		t.Fatalf("id = %q", id)
	}
	if got := doc.FindVerificationMethod(id).Type; got != jsonWebKeyVMType {
		t.Fatalf("type defaulted to %q, want %q", got, jsonWebKeyVMType)
	}

	// Same point, members in another order: still the same key.
	again := map[string]any{"y": jwkTestY, "x": jwkTestX, "crv": "secp256k1", "kty": "EC"}
	_, err = doc.AddVerificationMethod(VerificationMethod{Id: "#key-4", PublicKeyJwk: again}, nil)
	if err == nil || !strings.Contains(err.Error(), "same public key already exists: "+jwkTestDID+"#key-3") {
		t.Fatalf("second JWK of the same key: got %v", err)
	}
}

func TestAddVerificationMethod_JWKPublishesCIDContext(t *testing.T) {
	doc := oneDocWithKey1()
	for _, c := range doc.Context {
		if c == cidContext {
			t.Fatalf("precondition: a hex-only document has no CID context: %v", doc.Context)
		}
	}

	if _, err := doc.AddVerificationMethod(VerificationMethod{Id: "#key-3", PublicKeyJwk: sampleJWK()}, nil); err != nil {
		t.Fatalf("AddVerificationMethod: %v", err)
	}

	n := 0
	for _, c := range doc.Context {
		if c == cidContext {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("CID context appears %d times in %v, want once", n, doc.Context)
	}
}

func TestNewSecp256k1JsonWebKeyVM_SampleKey(t *testing.T) {
	for name, keyHex := range map[string]string{
		"compressed":    jwkTestKeyHex,
		"0x compressed": "0x" + jwkTestKeyHex,
		"uncompressed":  uncompressedHex(t, jwkTestKeyHex),
	} {
		t.Run(name, func(t *testing.T) {
			vm, err := NewSecp256k1JsonWebKeyVM(jwkTestDID, "#key-3", keyHex)
			if err != nil {
				t.Fatalf("NewSecp256k1JsonWebKeyVM: %v", err)
			}

			want := VerificationMethod{
				Id: jwkTestDID + "#key-3", Type: "JsonWebKey", Controller: jwkTestDID,
				PublicKeyJwk: sampleJWK(),
			}
			gotJSON, _ := json.Marshal(vm)
			wantJSON, _ := json.Marshal(want)
			if string(gotJSON) != string(wantJSON) {
				t.Fatalf("got  %s\nwant %s", gotJSON, wantJSON)
			}
		})
	}
}

// RFC 7518 6.2.1.2: x and y are the full coordinate length, leading zeros kept.
func TestNewSecp256k1JsonWebKeyVM_KeepsLeadingZeros(t *testing.T) {
	var pub *ecdsa.PublicKey
	for range 4096 {
		k, err := crypto.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		if k.X.BitLen() <= 248 {
			pub = &k.PublicKey
			break
		}
	}
	if pub == nil {
		t.Skip("no key with a short x found")
	}

	vm, err := NewSecp256k1JsonWebKeyVM(jwkTestDID, "#key-3", hex.EncodeToString(crypto.CompressPubkey(pub)))
	if err != nil {
		t.Fatalf("NewSecp256k1JsonWebKeyVM: %v", err)
	}
	if x := vm.PublicKeyJwk["x"].(string); len(x) != 43 {
		t.Fatalf("x %q is %d characters, want 43", x, len(x))
	}
	if _, err := vmTypeFor(vm); err != nil {
		t.Fatalf("the VM it builds must pass vmTypeFor: %v", err)
	}
}

func TestNewSecp256k1JsonWebKeyVM_RejectsBadHex(t *testing.T) {
	for _, bad := range []string{"", "0x1234", "zz", strings.Repeat("00", 33)} {
		if _, err := NewSecp256k1JsonWebKeyVM(jwkTestDID, "#key-3", bad); err == nil {
			t.Errorf("expected an error for %q", bad)
		}
	}
}

// A document holding #key-1 hex, #key-2 Multikey and #key-3 JWK of one scalar.
func TestGenerateDIDDocument_WithJsonWebKeyVM(t *testing.T) {
	kp, err := GenerateDualCurveKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	id := kp.GetDID("did:nda:testnet")

	p256VM, err := NewP256MultikeyVM(id, "#key-2", kp.P256PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := NewSecp256k1JsonWebKeyVM(id, "#key-3", kp.GetPublicKeyHex())
	if err != nil {
		t.Fatal(err)
	}

	doc := GenerateDIDDocument(kp.GetPublicKeyHex(), id, "", id, DIDTypePeople, nil, NewSpec(p256VM), NewSpec(jwk))
	if doc == nil {
		t.Fatal("GenerateDIDDocument returned nil")
	}
	if err := doc.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	key3 := doc.FindVerificationMethod("#key-3")
	if key3 == nil || key3.Type != jsonWebKeyVMType || key3.PublicKeyHex != "" {
		t.Fatalf("#key-3 = %+v", key3)
	}
	if !samePoint(t, key3.PublicKeyJwk, kp.GetPublicKeyHex()) {
		t.Fatal("#key-3 does not hold the point of #key-1")
	}
	for _, kid := range []string{"#key-1", "#key-2", "#key-3"} {
		if !containsKidRef(doc.Authentication, kid, id) || !containsKidRef(doc.AssertionMethod, kid, id) {
			t.Errorf("%s missing from a relationship array", kid)
		}
	}
	if !strings.Contains(strings.Join(doc.Context, " "), cidContext) {
		t.Errorf("CID context missing: %v", doc.Context)
	}
}

func TestGenerateDIDDocument_JWKAloneAddsCIDContext(t *testing.T) {
	jwk, err := NewSecp256k1JsonWebKeyVM(jwkTestDID, "#key-3", jwkTestKeyHex)
	if err != nil {
		t.Fatal(err)
	}

	doc := GenerateDIDDocument(jwkTestKeyHex, jwkTestDID, "", jwkTestDID, DIDTypePeople, nil, NewSpec(jwk))
	if doc == nil {
		t.Fatal("GenerateDIDDocument returned nil")
	}
	if got, want := strings.Join(doc.Context, " "),
		"https://www.w3.org/ns/did/v1 https://w3id.org/security/v1 "+cidContext; got != want {
		t.Fatalf("@context = %q, want %q", got, want)
	}
}

// A document read back from JSON (a registrar, the chain) carries the JWK as
// map[string]any with string values, and must still validate.
func TestValidate_JWKRoundTripsThroughJSON(t *testing.T) {
	jwk, err := NewSecp256k1JsonWebKeyVM(jwkTestDID, "#key-3", jwkTestKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	doc := GenerateDIDDocument(jwkTestKeyHex, jwkTestDID, "", jwkTestDID, DIDTypePeople, nil, NewSpec(jwk))

	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"publicKeyJwk":{"crv":"secp256k1","kty":"EC","x":"`+jwkTestX+`","y":"`+jwkTestY+`"}`) {
		t.Fatalf("JWK not serialized in RFC 7638 member order: %s", raw)
	}

	var back DIDDocument
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if err := back.Validate(); err != nil {
		t.Fatalf("Validate after a JSON round trip: %v", err)
	}
}

func uncompressedHex(t *testing.T, compressedHex string) string {
	t.Helper()

	raw, err := hex.DecodeString(compressedHex)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := crypto.DecompressPubkey(raw)
	if err != nil {
		t.Fatal(err)
	}

	return hex.EncodeToString(crypto.FromECDSAPub(pub))
}

func samePoint(t *testing.T, jwk map[string]any, keyHex string) bool {
	t.Helper()

	return jwk["x"] == mustJWKOf(t, keyHex)["x"] && jwk["y"] == mustJWKOf(t, keyHex)["y"]
}

func mustJWKOf(t *testing.T, keyHex string) map[string]any {
	t.Helper()

	vm, err := NewSecp256k1JsonWebKeyVM(jwkTestDID, "#k", keyHex)
	if err != nil {
		t.Fatal(err)
	}

	return vm.PublicKeyJwk
}

func mustP256JWK(t *testing.T) map[string]any {
	t.Helper()

	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw := priv.PublicKey().Bytes() // 0x04 || X || Y
	x, y := raw[1:33], raw[33:]

	return map[string]any{
		"kty": "EC", "crv": "P-256",
		"x": base64.RawURLEncoding.EncodeToString(x),
		"y": base64.RawURLEncoding.EncodeToString(y),
	}
}
