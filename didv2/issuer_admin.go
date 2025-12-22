package didv2

import (
	"context"
	"fmt"

	"github.com/pilacorp/go-credential-sdk/didv2/blockchain"
	"github.com/pilacorp/go-credential-sdk/didv2/signer"
)

// IssuerAdmin provides helpers for admin operations on the DID registry smart contract,
// such as granting ISSUER_ROLE to new issuers.
type IssuerAdmin struct {
	chainID  int64
	registry *blockchain.EthereumDIDRegistry
}

// NewIssuerAdmin creates a new IssuerAdmin using the same defaults as DIDGenerator
// when chainID or didAddress are not provided.
func NewIssuerAdmin(chainID int64, didAddress string) (*IssuerAdmin, error) {
	a := &IssuerAdmin{
		chainID: defaultChainID,
	}

	if chainID != 0 {
		a.chainID = chainID
	}
	if didAddress == "" {
		didAddress = defaultDIDAddress
	}

	registry, err := blockchain.NewEthereumDIDRegistry(didAddress, a.chainID)
	if err != nil {
		return nil, fmt.Errorf("failed to create registry: %w", err)
	}
	a.registry = registry

	return a, nil
}

// BuildAddIssuerTx creates a transaction payload that calls addIssuer on the registry
// contract (DIdRegistry.sol:110-116).
//
// - ctx:        context for transaction building
// - adminPkHex: hex-encoded private key of an account with ADMIN_ROLE
// - issuerAddr: address to grant ISSUER_ROLE
// - perms:      list of DID types the issuer is allowed to issue
func (a *IssuerAdmin) BuildAddIssuerTx(
	ctx context.Context,
	txSigner signer.Signer,
	issuerAddr string,
	perms []blockchain.DIDType,
) (*blockchain.SubmitTxResult, error) {
	if a.registry == nil {
		return nil, fmt.Errorf("registry not initialized")
	}

	return a.registry.AddIssuerTx(ctx, txSigner, issuerAddr, perms)
}
