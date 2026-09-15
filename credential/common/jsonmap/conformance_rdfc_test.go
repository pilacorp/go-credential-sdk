package jsonmap

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pilacorp/go-credential-sdk/credential/common/dto"
	"github.com/pilacorp/go-credential-sdk/credential/common/processor"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
)

// W3C ecdsa-rdfc-2019 byte-exact conformance gate (P-256).
//
// The vectors in testdata/w3c-rdfc-p256/ are the W3C worked example (inputs AND
// expected outputs authored by W3C/digitalbazaar, not by this repo). See
// testdata/w3c-rdfc-p256/SOURCE.md for provenance.
//
// Each phase recomputes one value from the published inputs and asserts
// byte-for-byte equality against the published expected value. The phases
// follow the order of section 3.2 of the spec, so the lowest-numbered failing
// phase is the actual defect — later failures are consequences of it.

const rdfcP256Dir = "testdata/w3c-rdfc-p256"

func rdfcRead(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(rdfcP256Dir, name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return b
}

// rdfcReadHex reads a fixture holding a hex digest and trims trailing newlines.
func rdfcReadHex(t *testing.T, name string) string {
	t.Helper()
	return strings.TrimSpace(string(rdfcRead(t, name)))
}

// rdfcSignedDoc is the published signed credential (document + proof).
func rdfcSignedDoc(t *testing.T) JSONMap {
	t.Helper()
	var m JSONMap
	if err := json.Unmarshal(rdfcRead(t, "signedECDSAP256.json"), &m); err != nil {
		t.Fatalf("parse signedECDSAP256.json: %v", err)
	}
	return m
}

// rdfcUnsignedDoc is the signed credential with the proof removed — the
// "transformed document" input of section 3.2.3.
func rdfcUnsignedDoc(t *testing.T) map[string]interface{} {
	t.Helper()
	var doc map[string]interface{}
	if err := json.Unmarshal(rdfcRead(t, "signedECDSAP256.json"), &doc); err != nil {
		t.Fatalf("parse signedECDSAP256.json: %v", err)
	}
	delete(doc, proofField)
	return doc
}

// rdfcProofConfig is the published proof configuration (proof options plus the
// document's @context), the input of section 3.2.5.
func rdfcProofConfig(t *testing.T) map[string]interface{} {
	t.Helper()
	var cfg map[string]interface{}
	if err := json.Unmarshal(rdfcRead(t, "proofConfigECDSAP256.json"), &cfg); err != nil {
		t.Fatalf("parse proofConfigECDSAP256.json: %v", err)
	}
	return cfg
}

// rdfcProof is the proof from the published signed credential.
func rdfcProof(t *testing.T) *dto.Proof {
	t.Helper()
	var wrapper struct {
		Proof dto.Proof `json:"proof"`
	}
	if err := json.Unmarshal(rdfcRead(t, "signedECDSAP256.json"), &wrapper); err != nil {
		t.Fatalf("parse proof: %v", err)
	}
	return &wrapper.Proof
}

// rdfcIssuerPub decodes the published P-256 issuer public key.
func rdfcIssuerPub(t *testing.T) *ecdsa.PublicKey {
	t.Helper()
	var kp struct {
		PublicKeyMultibase string `json:"publicKeyMultibase"`
		SecretKeyMultibase string `json:"secretKeyMultibase"`
	}
	if err := json.Unmarshal(rdfcRead(t, "p256KeyPair.json"), &kp); err != nil {
		t.Fatalf("parse p256KeyPair.json: %v", err)
	}
	pub, err := verificationmethod.ECPubFromMultibase(kp.PublicKeyMultibase)
	if err != nil {
		t.Fatalf("decode issuer public key: %v", err)
	}
	return pub
}

func TestW3CRDFCVectors_FixturesPresent(t *testing.T) {
	for _, name := range []string{
		"signedECDSAP256.json",
		"proofConfigECDSAP256.json",
		"canonDocECDSAP256.txt",
		"proofCanonECDSAP256.txt",
		"docHashECDSAP256.txt",
		"proofHashECDSAP256.txt",
		"combinedHashECDSAP256.txt",
		"sigHexECDSAP256.txt",
		"sigBTC58ECDSAP256.txt",
		"p256KeyPair.json",
		"SOURCE.md",
	} {
		if _, err := os.Stat(filepath.Join(rdfcP256Dir, name)); err != nil {
			t.Fatalf("missing W3C fixture %s: %v", name, err)
		}
	}
}

// Phase 1 (section 3.2.3, Transformation): URDNA2015 canonicalization of the
// credential without its proof must reproduce the published N-Quads exactly.
func TestW3CRDFC_Phase1_CanonicalizeDocument(t *testing.T) {
	got, err := processor.CanonicalizeNative(rdfcUnsignedDoc(t))
	if err != nil {
		t.Fatalf("canonicalize document: %v", err)
	}
	if want := rdfcRead(t, "canonDocECDSAP256.txt"); string(got) != string(want) {
		t.Fatalf("canonical document mismatch\n got:\n%s\nwant:\n%s", got, want)
	}
}

// Phase 2 (section 3.2.5, Proof Configuration): the proof options canonicalize
// to the published N-Quads.
func TestW3CRDFC_Phase2_CanonicalizeProofConfig(t *testing.T) {
	got, err := processor.CanonicalizeNative(rdfcProofConfig(t))
	if err != nil {
		t.Fatalf("canonicalize proof configuration: %v", err)
	}
	if want := rdfcRead(t, "proofCanonECDSAP256.txt"); string(got) != string(want) {
		t.Fatalf("canonical proof configuration mismatch\n got:\n%s\nwant:\n%s", got, want)
	}
}

// Phase 3 (section 3.2.4, Hashing): SHA-256 of each canonical form.
func TestW3CRDFC_Phase3_Hashes(t *testing.T) {
	docCanon, err := processor.CanonicalizeNative(rdfcUnsignedDoc(t))
	if err != nil {
		t.Fatalf("canonicalize document: %v", err)
	}
	docHash := sha256.Sum256(docCanon)
	if got, want := hex.EncodeToString(docHash[:]), rdfcReadHex(t, "docHashECDSAP256.txt"); got != want {
		t.Fatalf("docHash = %s, want %s", got, want)
	}

	cfgCanon, err := processor.CanonicalizeNative(rdfcProofConfig(t))
	if err != nil {
		t.Fatalf("canonicalize proof configuration: %v", err)
	}
	proofHash := sha256.Sum256(cfgCanon)
	if got, want := hex.EncodeToString(proofHash[:]), rdfcReadHex(t, "proofHashECDSAP256.txt"); got != want {
		t.Fatalf("proofHash = %s, want %s", got, want)
	}
}

// Phase 4 (section 3.2.4 step 3): hashData is proofConfigHash || documentHash.
// This exercises the production helper the signer and verifier both call, so it
// also pins the concatenation order — swapping it still round-trips against
// this SDK but breaks every other implementation.
func TestW3CRDFC_Phase4_HashData(t *testing.T) {
	doc := rdfcSignedDoc(t)
	got, err := doc.ecdsaHashData(rdfcProof(t))
	if err != nil {
		t.Fatalf("ecdsaHashData: %v", err)
	}
	if want := rdfcReadHex(t, "combinedHashECDSAP256.txt"); hex.EncodeToString(got) != want {
		t.Fatalf("hashData = %s, want %s", hex.EncodeToString(got), want)
	}
}

// Phase 5 (section 3.2.1 step 6): the proofValue is the multibase base58btc
// encoding of the raw signature, and matches the published encodings.
func TestW3CRDFC_Phase5_ProofValueEncoding(t *testing.T) {
	sigHex := rdfcReadHex(t, "sigHexECDSAP256.txt")
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		t.Fatalf("decode sigHex: %v", err)
	}
	if len(sig) != 64 {
		t.Fatalf("signature length = %d, want 64 (P-256 r||s)", len(sig))
	}

	if got, want := verificationmethod.EncodeMultibaseKey(sig), rdfcReadHex(t, "sigBTC58ECDSAP256.txt"); got != want {
		t.Fatalf("multibase signature = %s, want %s", got, want)
	}

	// The proofValue carried in the signed credential must decode to the same
	// bytes, so a verifier reading the credential recovers the published
	// signature.
	decoded, err := verificationmethod.DecodeMultibaseKey(rdfcProof(t).ProofValue)
	if err != nil {
		t.Fatalf("decode proofValue: %v", err)
	}
	if hex.EncodeToString(decoded) != sigHex {
		t.Fatalf("proofValue decodes to %s, want %s", hex.EncodeToString(decoded), sigHex)
	}
}

// Phase 6 (section 3.2.2, Proof Serialization): the published signature must
// verify over SHA-256(hashData) under the published P-256 issuer key. This is a
// standard-library check of the vector itself: it pins what a conformant
// verifier has to compute, independently of this SDK's verification path.
func TestW3CRDFC_Phase6_SignatureVerifiesOnP256(t *testing.T) {
	doc := rdfcSignedDoc(t)
	hashData, err := doc.ecdsaHashData(rdfcProof(t))
	if err != nil {
		t.Fatalf("ecdsaHashData: %v", err)
	}
	digest := sha256.Sum256(hashData)

	sig, err := hex.DecodeString(rdfcReadHex(t, "sigHexECDSAP256.txt"))
	if err != nil {
		t.Fatalf("decode sigHex: %v", err)
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])

	if !ecdsa.Verify(rdfcIssuerPub(t), digest[:], r, s) {
		t.Fatalf("published P-256 signature does not verify over SHA-256(hashData)")
	}
}

// rdfcDIDKeyResolver resolves the P-256 did:key used by the W3C vector, so
// VerifyProof can run without a network resolver.
type rdfcDIDKeyResolver struct{}

func (rdfcDIDKeyResolver) ResolveDocument(_ context.Context, did string) (*verificationmethod.DIDDocument, error) {
	multibaseKey := strings.TrimPrefix(did, "did:key:")
	pub, err := verificationmethod.ECPubFromMultibase(multibaseKey)
	if err != nil {
		return nil, err
	}
	return verificationmethod.NewDIDDocument(did, verificationmethod.NewP256VM(did, multibaseKey, pub)), nil
}

// Phase 7: the full public verification path accepts the W3C credential
// unchanged, and rejects it once a single character of the proofValue is
// changed. Together these show the verifier is bound to the published bytes
// rather than merely parsing them.
//
// Both directions live in one test on purpose. A verifier that rejects
// everything passes the tamper check for the wrong reason, so the acceptance
// check has to gate it: if the pristine credential does not verify, this test
// stops rather than reporting a rejection it did not earn.
func TestW3CRDFC_Phase7_VerifyProof(t *testing.T) {
	doc := rdfcSignedDoc(t)
	ok, err := doc.VerifyProof(rdfcDIDKeyResolver{}, "")
	if err != nil {
		t.Fatalf("VerifyProof on the unmodified W3C credential: %v", err)
	}
	if !ok {
		t.Fatalf("VerifyProof = false on the unmodified W3C credential, want true")
	}

	tampered := rdfcSignedDoc(t)
	proof, _ := tampered[proofField].(map[string]interface{})
	if proof == nil {
		t.Fatalf("signed credential has no proof object")
	}
	pv, _ := proof["proofValue"].(string)
	if pv == "" {
		t.Fatalf("signed credential has no proofValue")
	}
	// Flip one character in the middle of the signature.
	i := len(pv) / 2
	swap := byte('A')
	if pv[i] == 'A' {
		swap = 'B'
	}
	proof["proofValue"] = pv[:i] + string(swap) + pv[i+1:]

	if ok, err := tampered.VerifyProof(rdfcDIDKeyResolver{}, ""); ok && err == nil {
		t.Fatalf("VerifyProof accepted a credential with a tampered proofValue")
	}
}
