package jsonmap

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/pilacorp/go-credential-sdk/credential/common/dto"
	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
)

// ===== Test helpers =====

// p256Signer generates a random P-256 key pair and returns a signer + public key.
func p256Signer(t testing.TB) (signer.SignerProvider, *ecdsa.PublicKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-256 key: %v", err)
	}
	sp, err := signer.NewP256Provider(priv)
	if err != nil {
		t.Fatalf("P256Provider: %v", err)
	}
	return sp, &priv.PublicKey
}

// signedCredential returns a credential with n ecdsa-rdfc-2019 proofs, all from
// distinct verification methods on the same DID. The resolver resolves that DID.
func signedCredential(t testing.TB, n int) (JSONMap, verificationmethod.ResolverProvider) {
	t.Helper()
	const did = "did:example:issuer"

	type keyEntry struct {
		sp  signer.SignerProvider
		pub *ecdsa.PublicKey
		vm  verificationmethod.VerificationMethodEntry
	}

	keys := make([]keyEntry, n)
	for i := range keys {
		sp, pub := p256Signer(t)
		frag := fmt.Sprintf("key-%d", i+1)
		vm, err := verificationmethod.NewP256VM(did, frag, pub)
		if err != nil {
			t.Fatalf("vm %d: %v", i, err)
		}
		keys[i] = keyEntry{sp, pub, vm}
	}

	m := testCredential()
	m["issuer"] = did
	for i, k := range keys {
		if err := (&m).AddECDSAProof(k.sp, k.vm.ID, "assertionMethod", WithVMPublicKey(k.pub)); err != nil {
			t.Fatalf("sign proof %d: %v", i, err)
		}
	}

	vms := make([]verificationmethod.VerificationMethodEntry, len(keys))
	for i := range keys {
		vms[i] = keys[i].vm
	}
	resolver := verificationmethod.NewStaticResolver(
		verificationmethod.NewDIDDocument(did, vms...),
	)
	return m, resolver
}

// verifyWithCache runs verifyProofSet with its own cache and returns both the
// result and the cache's miss count.
func verifyWithCache(t testing.TB, m *JSONMap, resolver verificationmethod.ResolverProvider) (ok bool, misses int) {
	t.Helper()
	proofs, err := m.Proofs()
	if err != nil {
		t.Fatalf("Proofs: %v", err)
	}
	raw := m.rawProofList()
	cache := &digestCache{}
	ok, err = m.verifyProofSet(resolver, proofs, "", raw, cache)
	if err != nil {
		t.Fatalf("verifyProofSet: %v", err)
	}
	return ok, cache.misses
}

// signedSDCredential returns a credential with n ecdsa-sd-2023 derived proofs,
// each signed by a distinct P-256 key on the same DID. Each base proof uses a
// different random HMAC key (different issuance), producing distinct proof
// values. The resolver resolves the issuer DID with all VMs.
func signedSDCredential(t testing.TB, n int) (JSONMap, verificationmethod.ResolverProvider) {
	t.Helper()
	const did = "did:example:sd-issuer"

	type keyEntry struct {
		sp  signer.SignerProvider
		pub *ecdsa.PublicKey
		vm  verificationmethod.VerificationMethodEntry
	}
	keys := make([]keyEntry, n)
	for i := range keys {
		sp, pub := p256Signer(t)
		frag := fmt.Sprintf("key-%d", i+1)
		vm, err := verificationmethod.NewP256VM(did, frag, pub)
		if err != nil {
			t.Fatalf("vm %d: %v", i, err)
		}
		keys[i] = keyEntry{sp, pub, vm}
	}

	body := testCredential()
	body["issuer"] = did
	bodyJSON, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}

	// Each key signs its own base proof over the same body and derives the
	// same reveal, so every derived document has one body; the first one is
	// kept and the derived proofs are put on it as a set.
	result := JSONMap{}
	derivedProofs := make([]dto.Proof, 0, n)
	for i, k := range keys {
		var base JSONMap
		if err := json.Unmarshal(bodyJSON, &base); err != nil {
			t.Fatalf("unmarshal body: %v", err)
		}
		if err := base.AddECDSASDBaseProof(k.sp, k.vm.ID, "assertionMethod",
			[]string{"/issuer", "/issuanceDate"}, WithVMPublicKey(k.pub)); err != nil {
			t.Fatalf("add sd base proof %d: %v", i, err)
		}
		derived, err := base.DeriveECDSASD([]string{"/credentialSubject"})
		if err != nil {
			t.Fatalf("derive sd proof %d: %v", i, err)
		}
		if i == 0 {
			for key, v := range derived {
				if key != proofField {
					result[key] = v
				}
			}
		}
		proofs, err := derived.Proofs()
		if err != nil || len(proofs) != 1 {
			t.Fatalf("derived proofs %d: %d, %v", i, len(proofs), err)
		}
		derivedProofs = append(derivedProofs, proofs[0])
	}

	// Set the proof array.
	proofArr := make([]interface{}, n)
	for i, p := range derivedProofs {
		proofArr[i] = p.ToMap()
	}
	result[proofField] = proofArr

	vms := make([]verificationmethod.VerificationMethodEntry, len(keys))
	for i := range keys {
		vms[i] = keys[i].vm
	}
	resolver := verificationmethod.NewStaticResolver(
		verificationmethod.NewDIDDocument(did, vms...),
	)
	return result, resolver
}

// ===== Canonicalization count tests =====
//
// These tests use verifyProofSet with their own digestCache, so they can
// run in parallel and inspect cache.misses without a shared counter.

func TestVerifyProof_OneProof_CanonicalizesOnce(t *testing.T) {
	t.Parallel()
	m, resolver := signedCredential(t, 1)

	ok, misses := verifyWithCache(t, &m, resolver)
	if !ok {
		t.Fatal("VerifyProof = false, want true")
	}
	if misses != 1 {
		t.Fatalf("misses = %d, want 1 (one for one rdfc proof)", misses)
	}
}

func TestVerifyProof_FiveProofs_CanonicalizesOnce(t *testing.T) {
	t.Parallel()
	m, resolver := signedCredential(t, 5)

	ok, misses := verifyWithCache(t, &m, resolver)
	if !ok {
		t.Fatal("VerifyProof = false, want true")
	}
	// 5 ecdsa-rdfc-2019 proofs sharing the same body form: exactly 1 miss.
	if misses != 1 {
		t.Fatalf("misses = %d, want 1 (body canonicalized once for 5 rdfc proofs)", misses)
	}
}

func TestVerifyProof_SDProofs_CanonicalizesOnce(t *testing.T) {
	t.Parallel()
	m, resolver := signedSDCredential(t, 3)

	ok, misses := verifyWithCache(t, &m, resolver)
	if !ok {
		t.Fatal("VerifyProof = false, want true for 3 sd proofs")
	}
	// 3 ecdsa-sd-2023 proofs on the same body: exactly 1 sd canonicalization.
	if misses != 1 {
		t.Fatalf("misses = %d, want 1 (sd body canonicalized once for 3 proofs)", misses)
	}
}

func TestVerifyProof_MixedRDFCAndSD_CanonicalizesOnce(t *testing.T) {
	t.Parallel()
	m, sdResolver := signedSDCredential(t, 1)
	sdDoc, err := sdResolver.ResolveDocument(context.Background(), "did:example:sd-issuer")
	if err != nil {
		t.Fatal(err)
	}
	sp, pub := p256Signer(t)
	vm, err := verificationmethod.NewP256VM("did:example:sd-issuer", "rdfc", pub)
	if err != nil {
		t.Fatal(err)
	}
	if err := (&m).AddECDSAProof(sp, vm.ID, "assertionMethod", WithVMPublicKey(pub)); err != nil {
		t.Fatal(err)
	}
	resolver := verificationmethod.NewStaticResolver(
		verificationmethod.NewDIDDocument("did:example:sd-issuer", append(sdDoc.VerificationMethod, vm)...),
	)

	ok, misses := verifyWithCache(t, &m, resolver)
	if !ok {
		t.Fatal("VerifyProof = false, want true for one sd and one rdfc proof")
	}
	if misses != 1 {
		t.Fatalf("misses = %d, want 1 (rdfc and sd share the body N-Quads)", misses)
	}
}

// A derived proof value whose CBOR does not parse is refused with the parse
// error, before the body is canonicalized.
func TestVerifyProof_SDMalformedProofValue_RefusedBeforeCanonicalizing(t *testing.T) {
	t.Parallel()
	m, resolver := signedSDCredential(t, 1)
	proofs, err := m.Proofs()
	if err != nil {
		t.Fatalf("Proofs: %v", err)
	}
	// Derived header 0xd95d01, then the CBOR array [1, 2, 3].
	proofs[0].ProofValue = "u" + base64.RawURLEncoding.EncodeToString([]byte{0xd9, 0x5d, 0x01, 0x83, 0x01, 0x02, 0x03})

	cache := &digestCache{}
	_, err = m.verifyProofSet(resolver, proofs, "", m.rawProofList(), cache)
	if err == nil || !strings.Contains(err.Error(), "want 5 elements, got 3") {
		t.Fatalf("err = %v, want the derived proof parse error", err)
	}
	if cache.misses != 0 {
		t.Fatalf("misses = %d, want 0 (malformed proof value refused before canonicalizing)", cache.misses)
	}
}

// ===== Correctness tests =====

func TestVerifyProof_MultipleValidProofs(t *testing.T) {
	t.Parallel()
	for _, n := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("proofs=%d", n), func(t *testing.T) {
			t.Parallel()
			m, resolver := signedCredential(t, n)
			ok, err := m.VerifyProof(resolver, "")
			if err != nil {
				t.Fatalf("VerifyProof with %d valid proofs: %v", n, err)
			}
			if !ok {
				t.Fatalf("VerifyProof = false with %d valid proofs", n)
			}
		})
	}
}

func TestVerifyProof_OneInvalidAmongSeveral(t *testing.T) {
	t.Parallel()
	m, resolver := signedCredential(t, 3)

	// Tamper with the second proof's proofValue.
	proofs, ok := m[proofField].([]interface{})
	if !ok || len(proofs) < 3 {
		t.Fatal("expected proof array with 3 elements")
	}
	p1, ok := proofs[1].(map[string]interface{})
	if !ok {
		t.Fatal("expected proof map")
	}
	pv, _ := p1["proofValue"].(string)
	if pv == "" {
		t.Fatal("no proofValue on proof 1")
	}
	// Flip a character in the middle.
	i := len(pv) / 2
	swap := byte('A')
	if pv[i] == 'A' {
		swap = 'B'
	}
	p1["proofValue"] = pv[:i] + string(swap) + pv[i+1:]

	ok2, err := m.VerifyProof(resolver, "")
	// A one-character change in a base58btc proofValue still decodes and stays
	// 64 bytes, so the verifier reports a bad signature as (false, nil). The
	// "proof 1" error is covered by TestVerifyProof_ErrorsPreservedOrdering.
	if ok2 || err != nil {
		t.Fatalf("tampered proof: ok=%v err=%v, want false, nil", ok2, err)
	}
}

func TestVerifyProof_TargetVM_ChecksOnlyThatProof(t *testing.T) {
	t.Parallel()
	m, resolver := signedCredential(t, 3)
	proofs, err := m.Proofs()
	if err != nil || len(proofs) != 3 {
		t.Fatalf("expected 3 proofs, got %d: %v", len(proofs), err)
	}

	// Break proof 0; a targetVM of proof 1 must not look at it.
	p0 := m[proofField].([]interface{})[0].(map[string]interface{})
	pv := p0["proofValue"].(string)
	i := len(pv) / 2
	swap := byte('A')
	if pv[i] == 'A' {
		swap = 'B'
	}
	p0["proofValue"] = pv[:i] + string(swap) + pv[i+1:]

	if ok, err := m.VerifyProof(resolver, proofs[1].VerificationMethod); err != nil || !ok {
		t.Fatalf("targetVM of an intact proof: ok=%v err=%v, want true, nil", ok, err)
	}
	if ok, _ := m.VerifyProof(resolver, proofs[0].VerificationMethod); ok {
		t.Fatal("targetVM of the broken proof verified")
	}
}

// countingResolver wraps a resolver to count ResolveDocument calls.
type countingResolver struct {
	inner verificationmethod.ResolverProvider
	count int64
}

func (r *countingResolver) ResolveDocument(ctx context.Context, did string) (*verificationmethod.DIDDocument, error) {
	atomic.AddInt64(&r.count, 1)
	return r.inner.ResolveDocument(ctx, did)
}

func TestVerifyProof_OneDIDResolvedOnce(t *testing.T) {
	t.Parallel()
	m, inner := signedCredential(t, 3)
	resolver := &countingResolver{inner: inner}

	ok, err := m.VerifyProof(resolver, "")
	if err != nil || !ok {
		t.Fatalf("VerifyProof = %v, %v; want true, nil", ok, err)
	}
	if got := atomic.LoadInt64(&resolver.count); got != 1 {
		t.Fatalf("ResolveDocument calls = %d, want 1 (three proofs, one DID)", got)
	}
}

func TestVerifyProof_MaxProofs(t *testing.T) {
	t.Parallel()
	m, inner := signedCredential(t, 3)
	resolver := &countingResolver{inner: inner}

	_, err := m.VerifyProof(resolver, "", WithMaxProofs(2))
	if !errors.Is(err, ErrTooManyProofs) || !strings.Contains(err.Error(), "carries 3 and this verifier accepts at most 2") {
		t.Fatalf("WithMaxProofs(2) on 3 proofs: err = %v", err)
	}
	if got := atomic.LoadInt64(&resolver.count); got != 0 {
		t.Fatalf("ResolveDocument calls = %d, want 0 (refused before resolving)", got)
	}
	if ok, err := m.VerifyProof(resolver, "", WithMaxProofs(3)); err != nil || !ok {
		t.Fatalf("WithMaxProofs(3) on 3 proofs = %v, %v; want true, nil", ok, err)
	}
}

func TestVerifyProof_ErrorsPreservedOrdering(t *testing.T) {
	t.Parallel()
	// 2 proofs: first valid, second uses an unknown DID.
	const (
		did1 = "did:example:issuer1"
		did2 = "did:example:unknown"
	)

	sp1, pub1 := p256Signer(t)
	vm1, err := verificationmethod.NewP256VM(did1, "key-1", pub1)
	if err != nil {
		t.Fatal(err)
	}
	sp2, pub2 := p256Signer(t)
	_ = pub2 // second key's pub is not in the resolver

	m := testCredential()
	m["issuer"] = did1
	if err := (&m).AddECDSAProof(sp1, vm1.ID, "assertionMethod", WithVMPublicKey(pub1)); err != nil {
		t.Fatal(err)
	}
	if err := (&m).AddECDSAProof(sp2, did2+"#key-1", "assertionMethod", WithVMPublicKey(pub2)); err != nil {
		t.Fatal(err)
	}

	resolver := verificationmethod.NewStaticResolver(
		verificationmethod.NewDIDDocument(did1, vm1),
	)

	_, err = m.VerifyProof(resolver, "")
	if err == nil {
		t.Fatal("expected an error for unresolvable DID")
	}
	if !strings.Contains(err.Error(), "proof 1") {
		t.Fatalf("error should identify proof 1: %v", err)
	}
}
