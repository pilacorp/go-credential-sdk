package vccontract

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// lazyRPC is a URL ethclient.Dial accepts without connecting: an HTTP transport
// is built eagerly but dials on first use, so a constructor can be exercised
// without a chain. Nothing in these tests reaches the wire.
const lazyRPC = "http://127.0.0.1:1"

// A client that only reads logs has nothing to call, and used to be forced to
// name a contract anyway — which then silently became the first trusted address.
// Passing "" separates the two: whose logs to believe stays explicit, and no
// placeholder address has to be invented.
func TestNewCredentialRegistryAcceptsNoContractAddress(t *testing.T) {
	t.Parallel()

	registry, err := NewCredentialRegistry(lazyRPC, "", registryAddress.Hex(), legacyAddress.Hex())
	if err != nil {
		t.Fatalf("a log-reading client was refused: %v", err)
	}

	defer registry.Close()

	if registry.contract != nil {
		t.Fatal("bound a contract with no address; the view functions would call the zero address")
	}

	for _, want := range []common.Address{registryAddress, legacyAddress} {
		if !registry.trusts(want) {
			t.Fatalf("%s is not trusted; its logs would be dropped at the emitter check", want.Hex())
		}
	}
}

// And it still verifies. This is the point of the change: the call target was
// never needed to read a log, only the ABI and the trusted set.
func TestNoContractAddressStillReadsLogs(t *testing.T) {
	t.Parallel()

	registry, err := NewCredentialRegistry(lazyRPC, "", registryAddress.Hex())
	if err != nil {
		t.Fatalf("NewCredentialRegistry: %v", err)
	}

	defer registry.Close()

	want := mkLeaf(0xbb)
	registry.receipts = stubReceipts{receipt: successReceipt(
		batchLog(t, registryAddress, []common.Address{issuerAddress}, [][32]byte{want}),
	)}

	anchored, err := registry.IsRootAnchored(context.Background(), common.Hash{}, issuerAddress, want)
	if err != nil {
		t.Fatalf("IsRootAnchored: %v", err)
	}

	if !anchored {
		t.Fatal("a client without a call target could not read an anchoring from a log")
	}
}

// The three view functions are the only operations that call the contract, so
// they are the only ones a missing address breaks. Each has to say that, rather
// than call the zero address and report the RPC failure that follows — which would
// read as a chain problem instead of a configuration one.
func TestViewFunctionsReportTheMissingContractAddress(t *testing.T) {
	t.Parallel()

	registry, err := NewCredentialRegistry(lazyRPC, "", registryAddress.Hex())
	if err != nil {
		t.Fatalf("NewCredentialRegistry: %v", err)
	}

	defer registry.Close()

	leaf, sibling, _ := twoLeafTree()
	ctx := context.Background()

	calls := map[string]func() error{
		"VerifyVCHashOnChain": func() error {
			_, err := registry.VerifyVCHashOnChain(ctx, &VerifyRequest{
				IssuerAddress: issuerAddress.Hex(),
				Leaf:          hexOf(leaf),
				Proof:         []string{hexOf(sibling)},
			})

			return err
		},
		"GetTreeRoot": func() error {
			_, err := registry.GetTreeRoot(ctx, issuerAddress.Hex(), 1)

			return err
		},
		"HasTree": func() error {
			_, err := registry.HasTree(ctx, issuerAddress.Hex(), 1)

			return err
		},
	}

	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			if err := call(); !errors.Is(err, ErrNoContractAddress) {
				t.Fatalf("err = %v, want ErrNoContractAddress", err)
			}
		})
	}
}

// Naming no address is allowed and means "believe every emitter": a caller who
// does not want to enumerate deployments is not forced to.
//
// This test exists to state the cost in one place. The event signatures are
// public, so with the emitter check off, a contract anyone can deploy produces a
// log this client believes — and a forged anchoring naming an issuer the attacker
// does not control verifies as true. The two tests below are the proof, and they
// are what a reader should find before choosing this configuration.
func TestNewCredentialRegistryAllowsAnEmptyTrustedSet(t *testing.T) {
	t.Parallel()

	registry, err := NewCredentialRegistry(lazyRPC, "")
	if err != nil {
		t.Fatalf("naming no address was refused: %v", err)
	}

	defer registry.Close()

	if len(registry.trusted) != 0 {
		t.Fatalf("trusted set has %d entries, want none", len(registry.trusted))
	}

	if !registry.trusts(attackerAddress) {
		t.Fatal("an empty trusted set rejected an emitter; it is supposed to believe every one")
	}
}

// What that configuration costs, spelled out: a root anchored by nobody in
// particular verifies. The log here is emitted by an address that is not a
// deployment of this contract at all.
func TestAnEmptyTrustedSetBelievesAForgedAnchoring(t *testing.T) {
	t.Parallel()

	forged := mkLeaf(0xf0)

	registry, err := NewCredentialRegistry(lazyRPC, "")
	if err != nil {
		t.Fatalf("NewCredentialRegistry: %v", err)
	}

	defer registry.Close()

	registry.receipts = stubReceipts{receipt: successReceipt(
		singleLog(t, attackerAddress, issuerAddress, forged),
	)}

	anchored, err := registry.IsRootAnchored(context.Background(), common.Hash{}, issuerAddress, forged)
	if err != nil {
		t.Fatalf("IsRootAnchored: %v", err)
	}

	if !anchored {
		t.Fatal("expected the documented behaviour: with nothing trusted, any emitter is believed")
	}
}

// And the same log against a client that names one address: dropped. This is the
// check an empty set turns off, isolated to one assertion.
func TestNamingOneAddressRejectsTheSameForgedAnchoring(t *testing.T) {
	t.Parallel()

	forged := mkLeaf(0xf0)

	registry, err := NewCredentialRegistry(lazyRPC, "", registryAddress.Hex())
	if err != nil {
		t.Fatalf("NewCredentialRegistry: %v", err)
	}

	defer registry.Close()

	registry.receipts = stubReceipts{receipt: successReceipt(
		singleLog(t, attackerAddress, issuerAddress, forged),
	)}

	anchored, err := registry.IsRootAnchored(context.Background(), common.Hash{}, issuerAddress, forged)
	if err != nil {
		t.Fatalf("IsRootAnchored: %v", err)
	}

	if anchored {
		t.Fatal("a log from a contract outside the trusted set was believed")
	}
}

// common.IsHexAddress accepts the zero address, so an unset environment variable
// arrives here looking like a valid one. As contractAddress it produces a client
// whose every call goes nowhere; in alsoTrust it is inert but can only be a
// mistake. Refused in both, so neither needs explaining as a special case.
func TestNewCredentialRegistryRefusesTheZeroAddress(t *testing.T) {
	t.Parallel()

	const zero = "0x0000000000000000000000000000000000000000"

	for _, tc := range []struct {
		name            string
		contractAddress string
		alsoTrust       []string
	}{
		{"as contractAddress", zero, nil},
		{"as contractAddress with others trusted", zero, []string{registryAddress.Hex()}},
		{"in alsoTrust", registryAddress.Hex(), []string{zero}},
		{"in alsoTrust alongside a real one", registryAddress.Hex(), []string{legacyAddress.Hex(), zero}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewCredentialRegistry(lazyRPC, tc.contractAddress, tc.alsoTrust...); err == nil {
				t.Fatal("the zero address was accepted as a deployment")
			}
		})
	}
}

// A typo is a programming error in a library, not an operator's stale config, so
// it fails at construction rather than being dropped with a warning. The index
// tells the caller which entry.
func TestNewCredentialRegistryRefusesAMalformedAddress(t *testing.T) {
	t.Parallel()

	if _, err := NewCredentialRegistry(lazyRPC, "0xnope"); err == nil {
		t.Fatal("a malformed contractAddress was accepted")
	}

	_, err := NewCredentialRegistry(lazyRPC, registryAddress.Hex(), legacyAddress.Hex(), "0xnope")
	if err == nil {
		t.Fatal("a malformed alsoTrust entry was accepted")
	}

	if !strings.Contains(err.Error(), "index 1") {
		t.Fatalf("error %q does not name the offending entry", err)
	}
}
