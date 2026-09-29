// Command verifyonchain demonstrates VerifyVCHashOnChain, which asks the contract
// itself to check a proof against the tree's current stored root.
//
// DEPRECATED, AND KEPT ONLY FOR OLDER DEPLOYMENTS. The current contract has no
// verifyVC function and keeps no root in storage, so this call can only fail
// against it. Use the verifybytx example instead: it works against every
// deployment, current and past.
//
// The contract address below is a pre-upgrade deployment, which is the only kind
// this example can run against.
//
// The proof components (issuer address, tree index, leaf, and sibling proof) are
// assumed to already be in hand — for example, fetched from the authen-service
// proof API (GetVCProofByHash / GetVCProofByID).
//
// Run:
//
//	go run ./credential/examples/vccontract/verifyonchain
package main

import (
	"context"
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

	// Proof components (typically from the authen-service proof endpoint).
	req := &vccontract.VerifyRequest{
		IssuerAddress: "0xe4b13a02f5f06f4fc675550478208f39d1ee75bb",
		TreeIndex:     2,
		Leaf:          "0x01659e2bd15fe18252c9f03e0d948996e7d47a6c2dc22db4b9a89caa87699e98",
		Proof: []string{
			"0x01659e2bd15fe18252c9f03e0d948996e7d4ca6c2dc22db4b9a89caa87699e98",
		},
	}

	ctx := context.Background()

	ok, err := registry.VerifyVCHashOnChain(ctx, req)
	if err != nil {
		log.Fatalf("VerifyVCHashOnChain failed: %v", err)
	}

	if ok {
		fmt.Println("VC hash is anchored on-chain ✓")
	} else {
		fmt.Println("VC hash is NOT anchored on-chain ✗")
	}
}
