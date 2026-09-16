// Command verifybytx demonstrates how a client verifies that a VC hash is
// anchored by a SPECIFIC transaction, using vccontract.CredentialRegistry.
//
// This is the way to verify. It folds the Merkle proof locally into a root, then
// asks whether that exact root appears in the given transaction's logs, recorded
// for this issuer by a contract the client trusts. The contract keeps no root in
// storage, so those logs are the whole record of an anchoring.
//
// The proof components (issuer address, leaf, sibling proof, and the anchoring tx
// hash) are assumed to already be in hand — for example, from the authen-service
// proof API (GetVCProofByHash / GetVCProofByID), whose response carries the
// TxHash of the anchoring.
//
// No tree index is involved. The contract records an anchoring as (issuer, root),
// so the folded root is what the lookup is keyed on.
//
// Run:
//
//	go run ./credential/examples/vccontract/verifybytx
package main

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/pilacorp/go-credential-sdk/credential/vccontract"
)

func main() {
	const (
		rpcURL          = "https://rpc-testnet-new.pila.vn"
		contractAddress = "0x...CurrentDeployment"
		// Every earlier deployment whose anchorings must keep verifying. A tree
		// stays verifiable at the contract that anchored it and nothing re-anchors
		// it, so leaving an address out here makes every credential anchored by
		// that deployment read as never anchored.
		previousDeployment = "0x7F58Eb7eaEe52768970EC3796bdD146286EF82C6"
	)

	registry, err := vccontract.NewCredentialRegistry(rpcURL, contractAddress, previousDeployment)
	if err != nil {
		log.Fatalf("failed to create registry: %v", err)
	}
	defer registry.Close()

	// Proof components plus the anchoring tx hash (typically from the
	// authen-service proof endpoint).
	req := &vccontract.VerifyByTxRequest{
		IssuerAddress: "0xe4b13a02f5f06f4fc675550478208f39d1ee75bb",
		Leaf:          "0x01659e2bd15fe18252c9f07e0d948996e7d47a6c23c22db479a89caa87679e98",
		Proof: []string{
			"0x01659e2bd15fe18252c9f77e0d948996e7d47a6c23c22db479a89caa87679e98",
			"0x2065867413300fdd60d7155f38657ca04b1194d2ca4be86f575a4bdb6566304c",
			"0xe2a9e8aca918f473cf30c3f761535cbe687d49c27ad4c0ee9be3d7101b814b51",
		},
		TxHash: "0xd1432a03f29ebb9408c7bcc2fd557a535941293051245ec4d76116d3d10b42c4",
	}

	ctx := context.Background()

	ok, err := registry.VerifyVCHashByTx(ctx, req)
	if errors.Is(err, vccontract.ErrTxNotFound) {
		log.Fatalf("anchoring transaction not found or not yet mined")
	}
	if err != nil {
		log.Fatalf("VerifyVCHashByTx failed: %v", err)
	}

	if ok {
		fmt.Println("VC hash is anchored by the given transaction ✓")
	} else {
		fmt.Println("VC hash is NOT anchored by the given transaction ✗")
	}
}
