// Command verifybytx demonstrates how a client verifies that a VC hash is
// anchored by a SPECIFIC transaction, using vccontract.CredentialRegistry.
//
// Unlike the verifyonchain example (which checks the tree's current root via
// verifyVC), this folds the Merkle proof locally against the root that a given
// transaction recorded on-chain. Use it for an unsealed tree whose current root
// has since been overwritten by a later anchoring: the proof and the tx hash
// must come from the same anchoring.
//
// The proof components (issuer address, tree index, leaf, sibling proof, and the
// anchoring tx hash) are assumed to already be in hand — for example, from the
// authen-service proof API (GetVCProofByHash / GetVCProofByID), whose response
// carries the TxHash of the anchoring.
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
		contractAddress = "0x7F58Eb7eaEe52768970EC3796bdD146286EF82C6"
	)

	registry, err := vccontract.NewCredentialRegistry(rpcURL, contractAddress)
	if err != nil {
		log.Fatalf("failed to create registry: %v", err)
	}
	defer registry.Close()

	// Proof components plus the anchoring tx hash (typically from the
	// authen-service proof endpoint).
	req := &vccontract.VerifyByTxRequest{
		IssuerAddress: "0xe4b13a02f5f06f4fc675550478208f39d1ee75bb",
		TreeIndex:     6,
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
