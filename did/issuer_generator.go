package did

import (
	"context"
	"fmt"

	"github.com/pilacorp/go-credential-sdk/did/blockchain"
	"github.com/pilacorp/go-credential-sdk/did/signer"
)

type IssuerConfig struct {
	ChainID    int64
	DIDAddress string
	RPCURL     string
}

type OptionIssuer func(*IssuerConfig)

func WithChainID(chainID int64) OptionIssuer {
	return func(c *IssuerConfig) {
		c.ChainID = chainID
	}
}

func WithDIDAddress(didAddress string) OptionIssuer {
	return func(c *IssuerConfig) {
		c.DIDAddress = didAddress
	}
}

func WithRPCURL(rpcURL string) OptionIssuer {
	return func(c *IssuerConfig) {
		c.RPCURL = rpcURL
	}
}

func WithIssuerConfig(config *IssuerConfig) OptionIssuer {
	return func(c *IssuerConfig) {
		c.ChainID = config.ChainID
		c.DIDAddress = config.DIDAddress
		c.RPCURL = config.RPCURL
	}
}

// IssuerGenerator provides helpers for admin operations on the DID registry smart contract,
// such as granting ISSUER_ROLE to new issuers.
type IssuerGenerator struct {
	registry *blockchain.DIDContract
}

// NewIssuerGenerator creates a new IssuerAdmin using the same defaults as DIDGenerator
// when chainID or didAddress are not provided.
func NewIssuerGenerator(options ...OptionIssuer) (*IssuerGenerator, error) {
	config := executeOptionsIssuer(options...)

	if config.ChainID == 0 {
		config.ChainID = defaultChainIDV2
	}
	if config.DIDAddress == "" {
		config.DIDAddress = defaultDIDAddressV2
	}

	registry, err := blockchain.NewDIDContract(config.DIDAddress, config.ChainID, config.RPCURL)
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

func executeOptionsIssuer(options ...OptionIssuer) *IssuerConfig {
	configIssuer := &IssuerConfig{
		ChainID:    defaultChainIDV2,
		DIDAddress: defaultDIDAddressV2,
		RPCURL:     defaultRPCV2,
	}

	for _, opt := range options {
		opt(configIssuer)
	}

	return configIssuer
}
