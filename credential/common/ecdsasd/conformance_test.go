package ecdsasd

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	commoncrypto "github.com/pilacorp/go-credential-sdk/credential/common/crypto"
	"github.com/pilacorp/go-credential-sdk/credential/common/processor"
	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
)

// W3C ecdsa-sd-2023 byte-exact conformance gate.
//
// The vectors in testdata/w3c/ are the W3C worked example (inputs AND expected
// outputs authored by W3C/digitalbazaar, not by this repo). See
// testdata/w3c/SOURCE.md for provenance and how to verify them independently.
//
// Each phase test is a byte-exact assertion against the published W3C value. A
// green run means the implementation reproduces the W3C example exactly.

const w3cDir = "testdata/w3c"

type w3cKeyPair struct {
	PublicKeyMultibase string `json:"publicKeyMultibase"`
	SecretKeyMultibase string `json:"secretKeyMultibase"`
}

type w3cKeys struct {
	BaseKeyPair   w3cKeyPair `json:"baseKeyPair"`
	ProofKeyPair  w3cKeyPair `json:"proofKeyPair"`
	HMACKeyString string     `json:"hmacKeyString"`
}

type w3cExpected struct {
	HMACLabels  map[string]string `json:"hmacLabels"`
	ProofConfig struct {
		Type               string `json:"type"`
		Cryptosuite        string `json:"cryptosuite"`
		Created            string `json:"created"`
		VerificationMethod string `json:"verificationMethod"`
		ProofPurpose       string `json:"proofPurpose"`
	} `json:"proofConfig"`
	ProofHash      string `json:"proofHash"`
	MandatoryHash  string `json:"mandatoryHash"`
	BaseSignature  string `json:"baseSignature"`
	ProofPublicKey string `json:"proofPublicKey"`
	BaseProofValue string `json:"baseProofValue"`
	Derived        struct {
		SelectivePointers   []string          `json:"selectivePointers"`
		CombinedIndexes     []int             `json:"combinedIndexes"`
		MandatoryIndexes    []int             `json:"mandatoryIndexes"`
		NonMandatoryIndexes []int             `json:"nonMandatoryIndexes"`
		SelectiveIndexes    []int             `json:"selectiveIndexes"`
		AdjMandatoryIndexes []int             `json:"adjMandatoryIndexes"`
		LabelMap            map[string]string `json:"labelMap"`
		DerivedProofValue   string            `json:"derivedProofValue"`
	} `json:"derived"`
}

func w3cRead(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(w3cDir, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return b
}

func w3cLoadKeys(t *testing.T) w3cKeys {
	t.Helper()
	var k w3cKeys
	if err := json.Unmarshal(w3cRead(t, "keys.json"), &k); err != nil {
		t.Fatalf("parse keys.json: %v", err)
	}
	return k
}

func w3cLoadExpected(t *testing.T) w3cExpected {
	t.Helper()
	var e w3cExpected
	if err := json.Unmarshal(w3cRead(t, "expected.json"), &e); err != nil {
		t.Fatalf("parse expected.json: %v", err)
	}
	return e
}

// TestW3CVectors_FixturesPresent is a sanity check that the W3C fixtures load
// and contain the key anchors. Runs green today.
func TestW3CVectors_FixturesPresent(t *testing.T) {
	var cred map[string]interface{}
	if err := json.Unmarshal(w3cRead(t, "credential.json"), &cred); err != nil {
		t.Fatalf("parse credential.json: %v", err)
	}
	keys := w3cLoadKeys(t)
	if keys.HMACKeyString == "" || keys.BaseKeyPair.SecretKeyMultibase == "" {
		t.Fatal("keys.json missing keys")
	}
	exp := w3cLoadExpected(t)
	for _, v := range []string{exp.ProofHash, exp.MandatoryHash, exp.BaseProofValue, exp.Derived.DerivedProofValue} {
		if v == "" {
			t.Fatal("expected.json missing an anchor value")
		}
	}
	if len(w3cRead(t, "canonical.nq")) == 0 {
		t.Fatal("canonical.nq empty")
	}
}

// --- Phase gates (skip until implemented; then assert byte-exact) ---

func TestW3CConformance_Phase0_CanonicalizeWithIdMap(t *testing.T) {
	var cred map[string]interface{}
	if err := json.Unmarshal(w3cRead(t, "credential.json"), &cred); err != nil {
		t.Fatalf("parse credential.json: %v", err)
	}

	nquads, idMap, err := processor.CanonicalizeWithIdMap(cred)
	if err != nil {
		t.Fatalf("CanonicalizeWithIdMap: %v", err)
	}

	// (a) Canonical N-Quads must match Example 75 byte-for-byte.
	got := strings.Join(nquads, "")
	want := string(w3cRead(t, "canonical.nq"))
	if got != want {
		t.Fatalf("canonical N-Quads mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}

	// (b) HMAC labels derived from the canonical labels must match Example 76.
	keys := w3cLoadKeys(t)
	hmacKey, err := hex.DecodeString(keys.HMACKeyString)
	if err != nil {
		t.Fatalf("decode hmacKey: %v", err)
	}
	exp := w3cLoadExpected(t)
	seen := map[string]bool{}
	for _, c14n := range idMap {
		label := strings.TrimPrefix(c14n, "_:") // "_:c14n0" -> "c14n0"
		if seen[label] {
			continue
		}
		seen[label] = true
		mac := hmac.New(sha256.New, hmacKey)
		mac.Write([]byte(label))
		hmacLabel := "u" + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
		if w := exp.HMACLabels[label]; w != hmacLabel {
			t.Fatalf("HMAC label for %s = %s, want %s", label, hmacLabel, w)
		}
	}
	if len(seen) != len(exp.HMACLabels) {
		t.Fatalf("checked %d HMAC labels, expected %d (idMap incomplete?)", len(seen), len(exp.HMACLabels))
	}
}

func TestW3CConformance_Phase1_Multikey(t *testing.T) {
	keys := w3cLoadKeys(t)
	exp := w3cLoadExpected(t)

	// (a) p256-pub Multikey decode/encode round-trips.
	proofPubRaw, _, err := verificationmethod.DecodeP256PubMultibase(keys.ProofKeyPair.PublicKeyMultibase)
	if err != nil {
		t.Fatalf("decode proof pub: %v", err)
	}
	if got := verificationmethod.EncodeMultibaseKey(proofPubRaw); got != keys.ProofKeyPair.PublicKeyMultibase {
		t.Fatalf("proof pub round-trip: %s != %s", got, keys.ProofKeyPair.PublicKeyMultibase)
	}

	// (b) Secret-key Multikey derives the matching public-key Multikey.
	basePriv, err := verificationmethod.DecodeP256PrivMultibase(keys.BaseKeyPair.SecretKeyMultibase)
	if err != nil {
		t.Fatalf("decode base priv: %v", err)
	}
	if got := verificationmethod.EncodeP256PubMultibase(&basePriv.PublicKey); got != keys.BaseKeyPair.PublicKeyMultibase {
		t.Fatalf("derived base pub %s != %s", got, keys.BaseKeyPair.PublicKeyMultibase)
	}

	// (c) The W3C baseSignature verifies over proofHash||proofPub||mandatoryHash
	//     with the issuer (base) public key — validates key decode + signData
	//     assembly + P-256 verify against the published vector (Example 80/81).
	proofHash, err := hex.DecodeString(exp.ProofHash)
	if err != nil {
		t.Fatalf("proofHash: %v", err)
	}
	mandatoryHash, err := hex.DecodeString(exp.MandatoryHash)
	if err != nil {
		t.Fatalf("mandatoryHash: %v", err)
	}
	signData := make([]byte, 0, len(proofHash)+len(proofPubRaw)+len(mandatoryHash))
	signData = append(signData, proofHash...)
	signData = append(signData, proofPubRaw...)
	signData = append(signData, mandatoryHash...)
	digest := sha256.Sum256(signData)

	sig, err := hex.DecodeString(exp.BaseSignature)
	if err != nil {
		t.Fatalf("baseSignature: %v", err)
	}
	_, basePub, err := verificationmethod.DecodeP256PubMultibase(keys.BaseKeyPair.PublicKeyMultibase)
	if err != nil {
		t.Fatalf("decode base pub: %v", err)
	}
	if !commoncrypto.VerifyP256(basePub, digest[:], sig) {
		t.Fatal("W3C baseSignature failed to verify (key decode / signData assembly wrong)")
	}
}

func TestW3CConformance_Phase2_SelectJsonLd(t *testing.T) {
	var cred map[string]interface{}
	if err := json.Unmarshal(w3cRead(t, "credential.json"), &cred); err != nil {
		t.Fatalf("parse credential.json: %v", err)
	}
	var ptr struct {
		MandatoryPointers []string `json:"mandatoryPointers"`
		SelectivePointers []string `json:"selectivePointers"`
	}
	if err := json.Unmarshal(w3cRead(t, "pointers.json"), &ptr); err != nil {
		t.Fatalf("parse pointers.json: %v", err)
	}

	combined := append(append([]string{}, ptr.MandatoryPointers...), ptr.SelectivePointers...)
	got, err := selectJsonLd(cred, combined)
	if err != nil {
		t.Fatalf("selectJsonLd: %v", err)
	}

	var want map[string]interface{}
	if err := json.Unmarshal(w3cRead(t, "reveal.json"), &want); err != nil {
		t.Fatalf("parse reveal.json: %v", err)
	}

	if !reflect.DeepEqual(got, want) {
		gj, _ := json.MarshalIndent(got, "", "  ")
		wj, _ := json.MarshalIndent(want, "", "  ")
		t.Fatalf("selectJsonLd mismatch (Example 85):\n--- got ---\n%s\n--- want ---\n%s", gj, wj)
	}
}

func TestW3CConformance_Phase3_Grouping(t *testing.T) {
	var cred map[string]interface{}
	if err := json.Unmarshal(w3cRead(t, "credential.json"), &cred); err != nil {
		t.Fatalf("parse credential.json: %v", err)
	}
	keys := w3cLoadKeys(t)
	hmacKey, err := hex.DecodeString(keys.HMACKeyString)
	if err != nil {
		t.Fatalf("decode hmacKey: %v", err)
	}

	grouped, err := canonicalizeAndGroup(cred, hmacKey, map[string][]string{"mandatory": {"/issuer"}})
	if err != nil {
		t.Fatalf("canonicalizeAndGroup: %v", err)
	}

	if len(grouped.hmacNQuads) != 24 {
		t.Fatalf("expected 24 HMAC N-Quads, got %d", len(grouped.hmacNQuads))
	}

	mand := grouped.groups["mandatory"]
	gotMandatory := sortedIndexes(mand.matching)
	wantMandatory := []int{0, 12, 13, 17}
	if !reflect.DeepEqual(gotMandatory, wantMandatory) {
		t.Fatalf("mandatory indexes = %v, want %v (Example 77)", gotMandatory, wantMandatory)
	}
}

func w3cCred(t *testing.T) map[string]interface{} {
	t.Helper()
	var cred map[string]interface{}
	if err := json.Unmarshal(w3cRead(t, "credential.json"), &cred); err != nil {
		t.Fatalf("parse credential.json: %v", err)
	}
	return cred
}

func w3cProofConfig(exp w3cExpected) map[string]interface{} {
	return map[string]interface{}{
		"type":               exp.ProofConfig.Type,
		"cryptosuite":        exp.ProofConfig.Cryptosuite,
		"created":            exp.ProofConfig.Created,
		"verificationMethod": exp.ProofConfig.VerificationMethod,
		"proofPurpose":       exp.ProofConfig.ProofPurpose,
	}
}

func TestW3CConformance_Phase4_Hashes(t *testing.T) {
	cred := w3cCred(t)
	exp := w3cLoadExpected(t)
	keys := w3cLoadKeys(t)
	hmacKey, err := hex.DecodeString(keys.HMACKeyString)
	if err != nil {
		t.Fatalf("hmacKey: %v", err)
	}

	ph, err := hashProofConfig(w3cProofConfig(exp), cred["@context"])
	if err != nil {
		t.Fatalf("hashProofConfig: %v", err)
	}
	if got := hex.EncodeToString(ph); got != exp.ProofHash {
		t.Fatalf("proofHash = %s, want %s (Example 80)", got, exp.ProofHash)
	}

	grouped, err := canonicalizeAndGroup(cred, hmacKey, map[string][]string{"mandatory": {"/issuer"}})
	if err != nil {
		t.Fatalf("canonicalizeAndGroup: %v", err)
	}
	if got := hex.EncodeToString(hashMandatory(grouped.groups["mandatory"].matching)); got != exp.MandatoryHash {
		t.Fatalf("mandatoryHash = %s, want %s (Example 80)", got, exp.MandatoryHash)
	}
}

// Phase 5: full producer (createBaseProof) with real ephemeral signing, then
// derive and verify round-trip. Not byte-exact (random ephemeral key), but
// exercises the actual issuance crypto end-to-end against the W3C document.
func TestW3CConformance_Phase5_RoundTrip(t *testing.T) {
	cred := w3cCred(t)
	exp := w3cLoadExpected(t)
	keys := w3cLoadKeys(t)

	issuerPriv, err := verificationmethod.DecodeP256PrivMultibase(keys.BaseKeyPair.SecretKeyMultibase)
	if err != nil {
		t.Fatalf("issuer priv: %v", err)
	}
	issuerSigner, err := signer.NewP256Provider(issuerPriv)
	if err != nil {
		t.Fatalf("issuer signer: %v", err)
	}

	basePV, err := createBaseProof(cred, w3cProofConfig(exp), []string{"/issuer"}, issuerSigner)
	if err != nil {
		t.Fatalf("createBaseProof: %v", err)
	}

	dd, err := createDisclosureData(cred, basePV, exp.Derived.SelectivePointers)
	if err != nil {
		t.Fatalf("createDisclosureData: %v", err)
	}
	derivedPV, err := serializeDisclosureProofValue(&specDerivedProof{
		BaseSignature:    dd.baseSignature,
		PublicKey:        dd.publicKey,
		Signatures:       dd.signatures,
		LabelMap:         dd.labelMap,
		MandatoryIndexes: dd.mandatoryIndexes,
	})
	if err != nil {
		t.Fatalf("serialize derived: %v", err)
	}

	_, issuerPub, err := verificationmethod.DecodeP256PubMultibase(keys.BaseKeyPair.PublicKeyMultibase)
	if err != nil {
		t.Fatalf("issuer pub: %v", err)
	}
	if err := verifyDerivedProof(dd.revealDoc, w3cProofConfig(exp), derivedPV, issuerPub); err != nil {
		t.Fatalf("round-trip verify: %v", err)
	}
}

func TestW3CConformance_Phase6_BaseProofValue(t *testing.T) {
	exp := w3cLoadExpected(t)
	bp, err := parseBaseProofValue(exp.BaseProofValue)
	if err != nil {
		t.Fatalf("parseBaseProofValue: %v", err)
	}
	if hex.EncodeToString(bp.BaseSignature) != exp.BaseSignature {
		t.Fatalf("decoded baseSignature mismatch")
	}
	if verificationmethod.EncodeMultibaseKey(bp.PublicKey) != exp.ProofPublicKey {
		t.Fatalf("decoded publicKey = %s, want %s", verificationmethod.EncodeMultibaseKey(bp.PublicKey), exp.ProofPublicKey)
	}
	if len(bp.MandatoryPointers) != 1 || bp.MandatoryPointers[0] != "/issuer" {
		t.Fatalf("decoded mandatoryPointers = %v", bp.MandatoryPointers)
	}
	got, err := serializeBaseProofValue(bp)
	if err != nil {
		t.Fatalf("serializeBaseProofValue: %v", err)
	}
	if got != exp.BaseProofValue {
		t.Fatalf("base proofValue re-encode mismatch (Example 82):\ngot  %s\nwant %s", got, exp.BaseProofValue)
	}
}

func TestW3CConformance_Phase7_Derive(t *testing.T) {
	cred := w3cCred(t)
	exp := w3cLoadExpected(t)

	dd, err := createDisclosureData(cred, exp.BaseProofValue, exp.Derived.SelectivePointers)
	if err != nil {
		t.Fatalf("createDisclosureData: %v", err)
	}
	if !reflect.DeepEqual(dd.mandatoryIndexes, exp.Derived.AdjMandatoryIndexes) {
		t.Fatalf("relative mandatoryIndexes = %v, want %v (Example 87)", dd.mandatoryIndexes, exp.Derived.AdjMandatoryIndexes)
	}
	if !reflect.DeepEqual(dd.labelMap, exp.Derived.LabelMap) {
		t.Fatalf("derived labelMap = %v, want %v (Example 89)", dd.labelMap, exp.Derived.LabelMap)
	}
	if len(dd.signatures) != 6 {
		t.Fatalf("filtered signatures = %d, want 6 (Example 88)", len(dd.signatures))
	}

	got, err := serializeDisclosureProofValue(&specDerivedProof{
		BaseSignature:    dd.baseSignature,
		PublicKey:        dd.publicKey,
		Signatures:       dd.signatures,
		LabelMap:         dd.labelMap,
		MandatoryIndexes: dd.mandatoryIndexes,
	})
	if err != nil {
		t.Fatalf("serializeDisclosureProofValue: %v", err)
	}
	if got != exp.Derived.DerivedProofValue {
		t.Fatalf("derived proofValue mismatch (Appendix B):\ngot  %s\nwant %s", got, exp.Derived.DerivedProofValue)
	}
}

func TestW3CConformance_Phase8_VerifyDerived(t *testing.T) {
	cred := w3cCred(t)
	exp := w3cLoadExpected(t)
	keys := w3cLoadKeys(t)

	dd, err := createDisclosureData(cred, exp.BaseProofValue, exp.Derived.SelectivePointers)
	if err != nil {
		t.Fatalf("createDisclosureData: %v", err)
	}
	derivedPV, err := serializeDisclosureProofValue(&specDerivedProof{
		BaseSignature:    dd.baseSignature,
		PublicKey:        dd.publicKey,
		Signatures:       dd.signatures,
		LabelMap:         dd.labelMap,
		MandatoryIndexes: dd.mandatoryIndexes,
	})
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}

	_, issuerPub, err := verificationmethod.DecodeP256PubMultibase(keys.BaseKeyPair.PublicKeyMultibase)
	if err != nil {
		t.Fatalf("decode issuer pub: %v", err)
	}
	if err := verifyDerivedProof(dd.revealDoc, w3cProofConfig(exp), derivedPV, issuerPub); err != nil {
		t.Fatalf("verify derived (W3C round-trip): %v", err)
	}
}

// Deterministic ECDSA (RFC 6979, raw S — no low-S normalization) signing, used
// ONLY to reproduce the W3C worked-example proof value byte-for-byte. Production
// issuance uses fresh randomness (crypto/ecdsa). The reference cryptosuite signs
// deterministically (RFC 6979) and emits raw signatures, so injecting the
// vector's fixed hmacKey and ephemeral key reproduces the exact bytes.

func hmacSHA256(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

func bits2int(b []byte, qlen int) *big.Int {
	v := new(big.Int).SetBytes(b)
	if blen := len(b) * 8; blen > qlen {
		v.Rsh(v, uint(blen-qlen))
	}
	return v
}

func int2octets(v *big.Int, rolen int) []byte {
	out := make([]byte, rolen)
	v.FillBytes(out)
	return out
}

func bits2octets(b []byte, q *big.Int, qlen, rolen int) []byte {
	z1 := bits2int(b, qlen)
	z2 := new(big.Int).Sub(z1, q)
	if z2.Sign() < 0 {
		return int2octets(z1, rolen)
	}
	return int2octets(z2, rolen)
}

func rfc6979Nonce(d, q *big.Int, hash []byte) *big.Int {
	qlen := q.BitLen()
	rolen := (qlen + 7) / 8
	const holen = 32

	bx := append(int2octets(d, rolen), bits2octets(hash, q, qlen, rolen)...)

	v := bytes.Repeat([]byte{0x01}, holen)
	k := bytes.Repeat([]byte{0x00}, holen)
	k = hmacSHA256(k, append(append(append([]byte{}, v...), 0x00), bx...))
	v = hmacSHA256(k, v)
	k = hmacSHA256(k, append(append(append([]byte{}, v...), 0x01), bx...))
	v = hmacSHA256(k, v)

	for {
		var t []byte
		for len(t) < rolen {
			v = hmacSHA256(k, v)
			t = append(t, v...)
		}
		n := bits2int(t, qlen)
		if n.Sign() > 0 && n.Cmp(q) < 0 {
			return n
		}
		k = hmacSHA256(k, append(append([]byte{}, v...), 0x00))
		v = hmacSHA256(k, v)
	}
}

func hashToIntECDSA(hash []byte, q *big.Int) *big.Int {
	orderBytes := (q.BitLen() + 7) / 8
	if len(hash) > orderBytes {
		hash = hash[:orderBytes]
	}
	ret := new(big.Int).SetBytes(hash)
	if excess := len(hash)*8 - q.BitLen(); excess > 0 {
		ret.Rsh(ret, uint(excess))
	}
	return ret
}

func signRFC6979(priv *ecdsa.PrivateKey, hash []byte) []byte {
	c := priv.Curve
	q := c.Params().N
	k := rfc6979Nonce(priv.D, q, hash)
	kx, _ := c.ScalarBaseMult(k.Bytes()) //nolint:staticcheck // need scalar*G; stdlib has no non-deprecated path
	r := new(big.Int).Mod(kx, q)
	e := hashToIntECDSA(hash, q)
	kInv := new(big.Int).ModInverse(k, q)
	s := new(big.Int).Mul(r, priv.D)
	s.Add(s, e)
	s.Mul(s, kInv)
	s.Mod(s, q)
	// Note: the reference signer emits raw RFC 6979 signatures (no low-S
	// normalization), so we must NOT flip S here.
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return out
}

// createBaseProofDeterministic reproduces a base proof byte-for-byte given fixed
// randomness: hmacKey + ephemeral key + deterministic (RFC 6979) signing.
func createBaseProofDeterministic(document, proofConfig map[string]interface{}, mandatoryPointers []string, hmacKey []byte, ephemeralPriv, issuerPriv *ecdsa.PrivateKey) (string, error) {
	proofHash, err := hashProofConfig(proofConfig, document["@context"])
	if err != nil {
		return "", err
	}
	grouped, err := canonicalizeAndGroup(document, hmacKey, map[string][]string{"mandatory": mandatoryPointers})
	if err != nil {
		return "", err
	}
	mg := grouped.groups["mandatory"]
	nonMandatory := orderedValues(mg.nonMatching)
	mandatoryHash := hashMandatory(mg.matching)

	signatures := make([][]byte, len(nonMandatory))
	for i, nq := range nonMandatory {
		d := sha256.Sum256([]byte(nq))
		signatures[i] = signRFC6979(ephemeralPriv, d[:])
	}
	ephPub := verificationmethod.P256PubToMultikeyBytes(
		elliptic.MarshalCompressed(elliptic.P256(), ephemeralPriv.X, ephemeralPriv.Y))

	toSign := make([]byte, 0, len(proofHash)+len(ephPub)+len(mandatoryHash))
	toSign = append(toSign, proofHash...)
	toSign = append(toSign, ephPub...)
	toSign = append(toSign, mandatoryHash...)
	d := sha256.Sum256(toSign)
	baseSig := signRFC6979(issuerPriv, d[:])

	return serializeBaseProofValue(&specBaseProof{
		BaseSignature:     baseSig,
		PublicKey:         ephPub,
		HMACKey:           hmacKey,
		Signatures:        signatures,
		MandatoryPointers: mandatoryPointers,
	})
}

// Strongest issuance gate: regenerate the W3C base proof value byte-for-byte.
func TestW3CConformance_Phase5_ByteExactIssuance(t *testing.T) {
	cred := w3cCred(t)
	exp := w3cLoadExpected(t)
	keys := w3cLoadKeys(t)

	hmacKey, err := hex.DecodeString(keys.HMACKeyString)
	if err != nil {
		t.Fatalf("hmacKey: %v", err)
	}
	ephemeralPriv, err := verificationmethod.DecodeP256PrivMultibase(keys.ProofKeyPair.SecretKeyMultibase)
	if err != nil {
		t.Fatalf("ephemeral priv: %v", err)
	}
	issuerPriv, err := verificationmethod.DecodeP256PrivMultibase(keys.BaseKeyPair.SecretKeyMultibase)
	if err != nil {
		t.Fatalf("issuer priv: %v", err)
	}

	got, err := createBaseProofDeterministic(cred, w3cProofConfig(exp), []string{"/issuer"}, hmacKey, ephemeralPriv, issuerPriv)
	if err != nil {
		t.Fatalf("createBaseProofDeterministic: %v", err)
	}
	if got != exp.BaseProofValue {
		t.Fatalf("byte-exact issuance mismatch (Example 82):\ngot  %s\nwant %s", got, exp.BaseProofValue)
	}
}
