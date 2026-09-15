package didv2

import (
	"fmt"
	"sync"
	"testing"

	"github.com/pilacorp/go-credential-sdk/didv2/did"
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
