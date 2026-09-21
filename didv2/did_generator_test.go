package didv2

import (
	"fmt"
	"sync"
	"testing"

	"github.com/pilacorp/go-credential-sdk/didv2/did"
	"github.com/pilacorp/go-credential-sdk/didv2/signer"
)

// resolveConfig hands every caller a copy of baseConfig; the copy must own its
// ExtraVMs backing array, or per-call WithVerificationMethods appends (which
// GenerateDID always does) land in the shared one. Run under -race.
func TestResolveConfig_ExtraVMsCopyIsIndependent(t *testing.T) {
	var base []did.VerificationMethodSpec
	for i := 0; i < 3; i++ { // 3 appends leave spare capacity (len 3, cap 4)
		base = append(base, did.NewSpec(did.NewSecp256k1VM("did:nda:0xabc", fmt.Sprintf("#base-%d", i), "0x02aa")))
	}
	if cap(base) == len(base) {
		t.Skip("runtime left no spare capacity; the shared-slot scenario cannot be exercised")
	}
	g := &DIDGenerator{baseConfig: &DIDConfig{Method: "did:nda", CapID: "cap", ExtraVMs: base}}

	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			mine := did.NewSpec(did.NewSecp256k1VM("did:nda:0xabc", fmt.Sprintf("#mine-%d", i), "0x02aa"))
			cfg, err := g.resolveConfig(WithVerificationMethods(mine))
			if err != nil {
				t.Error(err)
				return
			}
			if len(cfg.ExtraVMs) != 4 || cfg.ExtraVMs[3].VM.Id != mine.VM.Id {
				t.Errorf("goroutine %d: ExtraVMs = %d entries, last %q; want 4 ending in %q",
					i, len(cfg.ExtraVMs), cfg.ExtraVMs[len(cfg.ExtraVMs)-1].VM.Id, mine.VM.Id)
			}
		}(i)
	}
	wg.Wait()

	if len(g.baseConfig.ExtraVMs) != 3 {
		t.Errorf("baseConfig.ExtraVMs grew to %d entries", len(g.baseConfig.ExtraVMs))
	}
}

// newOfflineGenerator builds a generator that never touches the chain: epoch and
// nonce stay at their defaults, so only the local signers are exercised.
func newOfflineGenerator(t *testing.T) *DIDGenerator {
	t.Helper()

	issuerKey, err := did.GenerateECDSAKeyPair()
	if err != nil {
		t.Fatalf("generate issuer key: %v", err)
	}
	issuerSigner, err := signer.NewDefaultProvider(issuerKey.GetPrivateKeyHex())
	if err != nil {
		t.Fatalf("issuer signer: %v", err)
	}

	g, err := NewDIDGenerator(WithIssuerSignerProvider(issuerSigner))
	if err != nil {
		t.Fatalf("new generator: %v", err)
	}
	return g
}

func vmIDs(doc *did.DIDDocument) []string {
	ids := make([]string, 0, len(doc.VerificationMethod))
	for _, vm := range doc.VerificationMethod {
		ids = append(ids, vm.Id)
	}
	return ids
}

// Default GenerateDID must publish only #key-1, so one on-chain attribute record
// still describes the document and the CID context stays out.
func TestGenerateDID_DefaultPublishesOneVM(t *testing.T) {
	res, err := newOfflineGenerator(t).GenerateDID(t.Context(), did.DIDTypeItem, "", nil)
	if err != nil {
		t.Fatalf("GenerateDID: %v", err)
	}

	if got := len(res.Document.VerificationMethod); got != 1 {
		t.Fatalf("got %d verification methods %v, want 1", got, vmIDs(res.Document))
	}
	if vm := res.Document.VerificationMethod[0]; vm.PublicKeyHex == "" || vm.PublicKeyMultibase != "" {
		t.Errorf("#key-1 must carry hex only: %+v", vm)
	}
	for _, ctx := range res.Document.Context {
		if ctx == "https://www.w3.org/ns/cid/v1" {
			t.Error("CID context published without a Multikey VM")
		}
	}
	if res.Secret == nil || res.Secret.PrivateKeyHex == "" {
		t.Error("secret missing: #key-2 could not be derived later")
	}
}

// WithP256VerificationMethod adds #key-2 as a Multikey and pulls in the CID context.
func TestGenerateDID_WithP256VM(t *testing.T) {
	res, err := newOfflineGenerator(t).GenerateDID(t.Context(), did.DIDTypeItem, "", nil, WithP256VerificationMethod())
	if err != nil {
		t.Fatalf("GenerateDID: %v", err)
	}

	if got := len(res.Document.VerificationMethod); got != 2 {
		t.Fatalf("got %d verification methods %v, want 2", got, vmIDs(res.Document))
	}

	var key2 did.VerificationMethod
	for _, vm := range res.Document.VerificationMethod {
		if vm.Id == res.DID+"#key-2" {
			key2 = vm
		}
	}
	if key2.Id == "" {
		t.Fatalf("no #key-2 in %v", vmIDs(res.Document))
	}
	if key2.Type != "Multikey" || key2.PublicKeyMultibase == "" || key2.PublicKeyHex != "" {
		t.Errorf("#key-2 must be a Multikey carrying multibase only: %+v", key2)
	}

	var hasCID bool
	for _, ctx := range res.Document.Context {
		if ctx == "https://www.w3.org/ns/cid/v1" {
			hasCID = true
		}
	}
	if !hasCID {
		t.Error("CID context missing for a Multikey VM")
	}
}
