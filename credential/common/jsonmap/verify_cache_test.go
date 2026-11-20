package jsonmap

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
)

// ===== Test seam: count canonicalization calls =====

// resetCanonicalizeCount zeroes canonicalizeCount and returns the value it had.
func resetCanonicalizeCount() int64 {
	return atomic.SwapInt64(&canonicalizeCount, 0)
}

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

// ===== Canonicalization count tests =====
//
// These tests assert the package-global canonicalizeCount. They must not use
// t.Parallel, and no other test that canonicalizes may run concurrently —
// the counter is shared across the whole package.

func TestVerifyProof_OneProof_CanonicalizesOnce(t *testing.T) {
	m, resolver := signedCredential(t, 1)
	resetCanonicalizeCount()

	ok, err := m.VerifyProof(resolver, "")
	if err != nil {
		t.Fatalf("VerifyProof: %v", err)
	}
	if !ok {
		t.Fatal("VerifyProof = false, want true")
	}

	// 1 proof: document body canonicalized once.
	count := atomic.LoadInt64(&canonicalizeCount)
	if count != 1 {
		t.Fatalf("DocumentDigest call count = %d, want 1 (one for one proof)", count)
	}
}

func TestVerifyProof_FiveProofs_CanonicalizesOnce(t *testing.T) {
	m, resolver := signedCredential(t, 5)
	resetCanonicalizeCount()

	ok, err := m.VerifyProof(resolver, "")
	if err != nil {
		t.Fatalf("VerifyProof: %v", err)
	}
	if !ok {
		t.Fatal("VerifyProof = false, want true")
	}

	// 5 proofs sharing the same body form: exactly 1 DocumentDigest call.
	count := atomic.LoadInt64(&canonicalizeCount)
	if count != 1 {
		t.Fatalf("DocumentDigest call count = %d, want 1 (body canonicalized once for 5 proofs)", count)
	}
}

// ===== Correctness tests =====

func TestVerifyProof_MultipleValidProofs(t *testing.T) {
	for _, n := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("proofs=%d", n), func(t *testing.T) {
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

func TestVerifyProof_TargetVM_SkipsCache(t *testing.T) {
	m, resolver := signedCredential(t, 3)

	// Get the second proof's verification method.
	proofs, err := m.Proofs()
	if err != nil || len(proofs) < 3 {
		t.Fatalf("expected 3 proofs, got %d: %v", len(proofs), err)
	}
	targetVM := proofs[1].VerificationMethod

	ok, err := m.VerifyProof(resolver, targetVM)
	if err != nil {
		t.Fatalf("VerifyProof with targetVM: %v", err)
	}
	if !ok {
		t.Fatal("VerifyProof = false with targetVM, want true")
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

func TestVerifyProof_ErrorsPreservedOrdering(t *testing.T) {
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

// ===== Benchmark =====

func BenchmarkVerifyProof(b *testing.B) {
	for _, nProofs := range []int{1, 5} {
		b.Run(fmt.Sprintf("proofs=%d", nProofs), func(b *testing.B) {
			m, resolver := signedCredential(b, nProofs)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				ok, err := m.VerifyProof(resolver, "")
				if err != nil {
					b.Fatal(err)
				}
				if !ok {
					b.Fatal("verification failed")
				}
			}
		})
	}
}
