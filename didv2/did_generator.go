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

// DIDGenerator handles DID generation and transaction creation.
type DIDGenerator struct {
	baseConfig  *DIDConfig
	didContract *didcontract.Contract
}

// NewDIDGenerator creates a new DIDGenerator.
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

// GenerateDID generates a new key pair and registers it as a DID.
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

// GenerateDIDTX creates a transaction to register a new DID.
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

// GenerateIssuerSignature generates an issuer signature.
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

// GenerateDIDCreateTransaction generates a DID create transaction.
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

// resolveConfig merges run-time options with the base configuration.
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
