package did

import (
	"context"
	"fmt"
	"strings"

	"github.com/pilacorp/go-credential-sdk/did/blockchain"
	"github.com/pilacorp/go-credential-sdk/did/signer"
)

// IssuerAdmin provides helpers for admin operations on the DID registry smart contract,
// such as granting ISSUER_ROLE to new issuers.
type IssuerAdmin struct {
	registry *blockchain.EthereumDIDRegistryV2
}

// NewIssuerAdmin creates a new IssuerAdmin using the same defaults as DIDGenerator
// when chainID or didAddress are not provided.
func NewIssuerAdmin(chainID int64, didAddress string, rpcURL string) (*IssuerAdmin, error) {
	if chainID == 0 {
		chainID = defaultChainID
	}
	if didAddress == "" {
		didAddress = defaultDIDAddress
	}

	registry, err := blockchain.NewEthereumDIDRegistryV2(strings.TrimPrefix(didAddress, "0x"), chainID, rpcURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create registry: %w", err)
	}

	return &IssuerAdmin{registry: registry}, nil
}

// CreateIssuerTx creates a transaction payload that calls addIssuer on the registry
// contract (DIdRegistry.sol:110-116).
//
// - ctx:        context for transaction building
// - txSigner:   signer for the transaction
// - issuerAddress: address of the issuer
// - perms:      list of DID types the issuer is allowed to issue
func (a *IssuerAdmin) CreateIssuerTx(
	ctx context.Context,
	txSigner signer.Signer,
	issuerAddress string,
	perms []blockchain.DIDType,
) (*blockchain.SubmitTxResult, error) {
	if a.registry == nil {
		return nil, fmt.Errorf("registry not initialized")
	}

	return a.registry.CreateIssuerTx(ctx, txSigner, issuerAddress, perms)
}
