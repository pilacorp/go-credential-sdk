package verificationmethod

import (
	"context"
	"fmt"
	"sync"
	"testing"
)

// Add and ResolveDocument may run concurrently (vc.Verify fans out its checks
// in an errgroup); run under -race to catch an unguarded map.
func TestStaticResolver_ConcurrentAddAndResolve(t *testing.T) {
	r := NewStaticResolver(NewDIDDocument("did:example:seed"))

	const n = 50
	var wg sync.WaitGroup
	wg.Add(2 * n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			r.Add(NewDIDDocument(fmt.Sprintf("did:example:%d", i)))
		}(i)
		go func() {
			defer wg.Done()
			if _, err := r.ResolveDocument(context.Background(), "did:example:seed"); err != nil {
				t.Errorf("resolve seed: %v", err)
			}
		}()
	}
	wg.Wait()

	for i := 0; i < n; i++ {
		did := fmt.Sprintf("did:example:%d", i)
		if _, err := r.ResolveDocument(context.Background(), did); err != nil {
			t.Errorf("resolve %s after concurrent Add: %v", did, err)
		}
	}
}

func TestStaticResolver_AddIgnoresNilAndEmptyID(t *testing.T) {
	r := NewStaticResolver()
	r.Add(nil)
	r.Add(&DIDDocument{})
	if _, err := r.ResolveDocument(context.Background(), ""); err == nil {
		t.Fatal("expected empty-ID document not to be registered")
	}
}
