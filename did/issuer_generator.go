package did

import (
	"context"
	"fmt"

	"github.com/pilacorp/go-credential-sdk/did/blockchain"
	"github.com/pilacorp/go-credential-sdk/did/signer"
)

// IssuerGenerator provides helpers for admin operations on the DID registry smart contract,
// such as granting ISSUER_ROLE to new issuers.
type IssuerGenerator struct {
	registry *blockchain.DIDContract
}

// NewIssuerGenerator creates a new IssuerAdmin using the same defaults as DIDGenerator
// when chainID or didAddress are not provided.
func NewIssuerGenerator(chainID int64, didAddress string, rpcURL string) (*IssuerGenerator, error) {
	if chainID == 0 {
		chainID = defaultChainID
	}
	if didAddress == "" {
		didAddress = defaultDIDAddress
	}

	registry, err := blockchain.NewDIDContract(didAddress, chainID, rpcURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create registry: %w", err)
	}

	return &IssuerGenerator{registry: registry}, nil
}

// AddIssuerTx creates a new addIssuer transaction.
//
// - txSigner:   signer for the transaction
// - issuerAddress: address of the issuer
// - perms:      list of DID types the issuer is allowed to issue
func (a *IssuerGenerator) AddIssuerTx(
	ctx context.Context,
	txSigner signer.Signer,
	signerAddress, issuerAddress string,
	permissions []blockchain.DIDType,
) (*blockchain.SubmitTxResult, error) {
	if a.registry == nil {
		return nil, fmt.Errorf("registry not initialized")
	}

	return a.registry.AddIssuerTx(ctx, txSigner, signerAddress, issuerAddress, permissions)
}
