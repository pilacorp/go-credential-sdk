// Package didv2 provides a Go SDK for generating Decentralized Identifiers (DIDs) with
// capability-based authorization on blockchain networks.
//
// The SDK follows an Issuer-centric DID model where DIDs are not considered valid
// without an Issuer Signature. The issuance process involves:
//   - Generating or using existing key pairs
//   - Creating DID Documents with metadata
//   - Generating Issuer Signatures for authorization
//   - Building blockchain-ready transactions
//
// The SDK supports two deployment models:
//   - Model 1: Single-service where one backend holds both Issuer and DID keys
//   - Model 2: Split model where Issuer and DID owner are in separate environments
//
// The SDK does not submit transactions to the blockchain. It only creates raw
// transactions that must be submitted separately.
//
// For complete documentation and examples, see:
// https://github.com/pilacorp/go-credential-sdk/tree/main/didv2
package didv2

import (
	"context"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/pilacorp/go-credential-sdk/didv2/did"
	"github.com/pilacorp/go-credential-sdk/didv2/didcontract"
	"github.com/pilacorp/go-credential-sdk/didv2/issuer"
	"github.com/pilacorp/go-credential-sdk/didv2/signer"
)

// DIDGenerator orchestrates the DID generation and transaction creation workflow.
//
// It serves as a facade/orchestrator that coordinates the following steps:
//   - Key pair generation (if needed)
//   - Issuer signature creation
//   - DID Document generation
//   - Transaction data preparation
type DIDGenerator struct {
	baseConfig  *DIDConfig
	didContract *didcontract.Contract
}

// NewDIDGenerator creates a new DIDGenerator instance with the provided configuration options.
//
// It initializes the DID contract client and applies the given options to configure
// the generator. If no options are provided, default values are used.
//
// Example:
//
//	generator, err := didv2.NewDIDGenerator(
//	    didv2.WithRPC("https://rpc-new.pila.vn"),
//	    didv2.WithIssuerSignerProvider(issuerSigner),
//	)
func NewDIDGenerator(options ...DIDOption) (*DIDGenerator, error) {
	cfg := DIDConfig{
		RPC:        DefaultRPC,
		ChainID:    DefaultChainID,
		DIDSMCAddr: DefaultDIDSMCAddress,
		Method:     DefaultMethod,
	}

	for _, opt := range options {
		opt(&cfg)
	}

	didContract, err := didcontract.NewContract(
		&didcontract.Config{
			RPCURL:          cfg.RPC,
			ContractAddress: cfg.DIDSMCAddr,
			ChainID:         cfg.ChainID,
		})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize did contract: %w", err)
	}

	return &DIDGenerator{
		baseConfig:  &cfg,
		didContract: didContract,
	}, nil
}

// GenerateDID generates a new key pair and creates a complete DID issuance workflow.
//
// This is a high-level API that automatically:
//   - Generates a new ECDSA key pair
//   - Creates an issuer signature
//   - Generates a DID Document
//   - Builds and signs a transaction
//
// The generated private key is included in the result's Secret field.
//
// The ctx parameter is used for blockchain queries (e.g., syncing epoch/nonce).
// The didType parameter specifies the type of DID (People, Item, Location, Activity).
// The hash parameter is an optional hash value to include in the DID Document metadata.
// The metadata parameter contains additional key-value pairs for the DID Document.
//
// Returns a DIDTxResult containing the DID identifier, document, transaction, and secret.
func (d *DIDGenerator) GenerateDID(
	ctx context.Context,
	didType did.DIDType,
	hash string,
	metadata map[string]any,
	options ...DIDOption,
) (*DIDTxResult, error) {
	// 1. Generate key pair.
	keyPair, err := did.GenerateECDSAKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	// init did signer from private key of did.
	didSigner, err := signer.NewDefaultProvider(keyPair.GetPrivateKeyHex())
	if err != nil {
		return nil, fmt.Errorf("failed to create did signer: %w", err)
	}

	options = append(options, WithDIDSignerProvider(didSigner))

	// 2. Generate DID TX.
	didTx, err := d.GenerateDIDTX(ctx, didType, keyPair.GetPublicKeyHex(), hash, metadata, options...)
	if err != nil {
		return nil, fmt.Errorf("failed to generate DID TX: %w", err)
	}

	// 3. add secret to did tx result.
	didTx.Secret = &Secret{PrivateKeyHex: keyPair.GetPrivateKeyHex()}

	return didTx, nil
}

// GenerateDIDTX creates a transaction to register a DID from an existing public key.
//
// This is a lower-level API that requires the DID public key to be provided.
// It performs the same workflow as GenerateDID but uses an existing key pair
// instead of generating a new one.
//
// This method is useful when:
//   - The key pair is generated separately
//   - You need to regenerate a transaction without creating a new key pair
//
// The ctx parameter is used for blockchain queries (e.g., syncing epoch/nonce).
// The didPublicKeyHex parameter must be a valid hex-encoded public key (compressed or uncompressed).
// The hash parameter is an optional hash value to include in the DID Document metadata.
// The metadata parameter contains additional key-value pairs for the DID Document.
//
// Requires an IssuerSigner to be configured (via options or base config).
// Returns a DIDTxResult containing the DID identifier, document, and transaction.
func (d *DIDGenerator) GenerateDIDTX(
	ctx context.Context,
	didType did.DIDType,
	didPublicKeyHex, hash string,
	metadata map[string]any,
	options ...DIDOption,
) (*DIDTxResult, error) {
	// 1. Resolve configuration.
	cfg, err := d.resolveConfig(options...)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve configuration: %w", err)
	}

	// 2. Create Issuer Signature.
	// require issuer signer valid.
	if cfg.IssuerSigner == nil {
		return nil, fmt.Errorf("issuer signer is required")
	}

	issuerAddr := cfg.IssuerSigner.GetAddress()
	didAddr, err := did.AddressFromPublicKeyHex(didPublicKeyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to convert public key hex to address: %w", err)
	}

	issuerSig, err := d.GenerateIssuerSignature(ctx, didType, didAddr, issuerAddr, WithDIDConfig(cfg))
	if err != nil {
		return nil, fmt.Errorf("failed to generate issuer signature: %w", err)
	}

	// 3. Generate DID Document.
	issuerDID := did.ToDID(cfg.Method, issuerAddr)
	didIdentifier := did.ToDID(cfg.Method, didAddr)

	didDoc := did.GenerateDIDDocument(didPublicKeyHex, didIdentifier, hash, issuerDID, didType, metadata)

	docHash, err := didDoc.Hash()
	if err != nil {
		return nil, fmt.Errorf("failed to hash DID document: %w", err)
	}

	// 4. Create DID Tx Transaction.
	txResult, err := d.GenerateDIDCreateTransaction(ctx, didType, docHash, didAddr, issuerAddr, issuerSig, WithDIDConfig(cfg))
	if err != nil {
		return nil, fmt.Errorf("failed to generate create DID transaction: %w", err)
	}

	// 5. To did result.
	return &DIDTxResult{
		DID:         didIdentifier,
		Document:    didDoc,
		Transaction: txResult,
	}, nil
}

// GenerateIssuerSignature generates an issuer signature for authorizing DID issuance.
//
// The issuer signature proves that the Issuer authorizes the creation of a specific DID.
// It is created by signing a capability payload (EIP-191 format) that includes:
//   - Contract address
//   - Issuer address
//   - DID address
//   - DID type
//   - Capability epoch
//   - Capability ID
//
// If SyncEpoch is enabled, the epoch is automatically fetched from the blockchain.
// If CapID is not provided, it is automatically generated.
//
// The ctx parameter is used for blockchain queries when syncing epoch.
// The didType parameter specifies the type of DID being issued.
// The didAddr parameter is the Ethereum address derived from the DID public key.
// The issuerAddr parameter is the Ethereum address of the Issuer.
//
// Requires an IssuerSigner to be configured (via options or base config).
// Returns an issuer Signature containing R, S, V components.
func (d *DIDGenerator) GenerateIssuerSignature(
	ctx context.Context,
	didType did.DIDType,
	didAddr, issuerAddr string,
	options ...DIDOption,
) (*issuer.Signature, error) {
	cfg, err := d.resolveConfig(options...)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve configuration: %w", err)
	}

	// require RPC URL valid.
	// this is optional field, if not set, will use default value is zero.
	if cfg.SyncEpoch {
		epoch, err := d.didContract.GetCapabilityEpoch(ctx, issuerAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to get capability epoch: %w", err)
		}

		cfg.Epoch = epoch
	}

	issueDIDPayload := &issuer.IssueDIDPayload{
		ContractAddress: d.baseConfig.DIDSMCAddr,
		IssuerAddress:   issuerAddr,
		DidAddress:      didAddr,
		DidType:         didType,
		Epoch:           cfg.Epoch,
		CapID:           cfg.CapID,
	}

	issuerSig, err := issuer.GenerateIssueDIDSignature(issueDIDPayload, cfg.IssuerSigner)
	if err != nil {
		return nil, fmt.Errorf("failed to create issuer signature: %w", err)
	}

	return issuerSig, nil
}

// GenerateDIDCreateTransaction generates a signed raw transaction for creating a DID on-chain.
//
// This method builds the transaction data and signs it using the DID signer to create
// a raw transaction ready for blockchain submission.
//
// If SyncNonce is enabled, the nonce is automatically fetched from the blockchain.
// Otherwise, the nonce from the configuration (default 0) is used.
//
// The ctx parameter is used for blockchain queries when syncing nonce.
// The didType parameter specifies the type of DID.
// The docHash parameter is the hash of the DID Document (from DIDDocument.Hash()).
// The didAddr parameter is the Ethereum address of the DID.
// The issuerAddr parameter is the Ethereum address of the Issuer.
// The issuerSig parameter is the issuer signature authorizing the DID creation.
//
// Requires a DIDSigner to be configured (via options or base config).
// Returns a Transaction containing the raw transaction hex and transaction hash.
func (d *DIDGenerator) GenerateDIDCreateTransaction(
	ctx context.Context,
	didType did.DIDType,
	docHash, didAddr, issuerAddr string,
	issuerSig *issuer.Signature,
	options ...DIDOption,
) (*didcontract.Transaction, error) {
	cfg, err := d.resolveConfig(options...)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve configuration: %w", err)
	}

	// require RPC URL valid.
	// this is optional field, if not set, will use default value is zero.
	if cfg.SyncNonce {
		nonce, err := d.didContract.GetNonce(ctx, common.HexToAddress(didAddr))
		if err != nil {
			return nil, fmt.Errorf("failed to get nonce: %w", err)
		}

		cfg.Nonce = nonce
	}

	didCreateTxReq := &didcontract.CreateDIDRequest{
		IssuerAddress: issuerAddr,
		IssuerSig:     issuerSig,
		DocHash:       docHash,
		DIDType:       didType,
		CapID:         cfg.CapID,
		Nonce:         cfg.Nonce,
	}

	txResult, err := d.didContract.CreateDIDTx(ctx, didCreateTxReq, cfg.DIDSigner)
	if err != nil {
		return nil, fmt.Errorf("failed to generate DID TX from issuer signature: %w", err)
	}

	return txResult, nil
}

// resolveConfig merges runtime options with the base configuration.
//
// It applies all provided options to the base config and automatically generates
// a CapID if one is not provided. This is an internal method used by public APIs.
func (d *DIDGenerator) resolveConfig(options ...DIDOption) (*DIDConfig, error) {
	cfg := d.baseConfig
	for _, opt := range options {
		opt(cfg)
	}

	// auto generate cap ID if not set.
	if cfg.CapID == "" {
		hexStr, err := issuer.GenerateCapID()
		if err != nil {
			return nil, fmt.Errorf("failed to generate cap ID: %w", err)
		}

		cfg.CapID = hexStr
	}

	return cfg, nil
}
