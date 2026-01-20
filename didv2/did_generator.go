package didv2

import (
	"context"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/pilacorp/go-credential-sdk/didv2/blockchain"
	"github.com/pilacorp/go-credential-sdk/didv2/signer"
)

// DIDGenerator handles DID generation and transaction creation.
type DIDGenerator struct {
	baseConfig DIDConfig
	registry   *blockchain.DIDContract
}

// NewDIDGenerator creates a new DIDGenerator.
func NewDIDGenerator(options ...DIDOption) (*DIDGenerator, error) {
	cfg := DIDConfig{
		RPC:           DefaultRPC,
		ChainID:       DefaultChainID,
		DIDSMCAddress: DefaultDIDSMCAddress,
		Method:        DefaultMethod,
	}

	for _, opt := range options {
		opt(&cfg)
	}

	if cfg.RPC == "" {
		return nil, fmt.Errorf("RPC URL is required")
	}
	if cfg.DIDSMCAddress == "" {
		return nil, fmt.Errorf("DID contract address is required")
	}

	clientCfg := blockchain.ClientConfig{
		RPCURL:          cfg.RPC,
		ContractAddress: cfg.DIDSMCAddress,
		ChainID:         cfg.ChainID,
		GasLimit:        300000,
	}

	registry, err := blockchain.NewDIDContract(clientCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize blockchain client: %w", err)
	}

	return &DIDGenerator{
		baseConfig: cfg,
		registry:   registry,
	}, nil
}

// GenerateDID generates a new key pair and registers it as a DID.
func (d *DIDGenerator) GenerateDID(
	ctx context.Context,
	didType blockchain.DIDType,
	hash string,
	metadata map[string]interface{},
	options ...DIDOption,
) (*DID, error) {
	cfg := d.resolveConfig(options...)

	keyPair, err := GenerateECDSAKeyPair(cfg.Method)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	return d.GenerateDIDTX(ctx, didType, keyPair, hash, metadata, WithDIDConfig(&cfg))
}

// GenerateDIDTX creates a transaction to register an existing key pair.
func (d *DIDGenerator) GenerateDIDTX(
	ctx context.Context,
	didType blockchain.DIDType,
	keyPair *KeyPair,
	hash string,
	metadata map[string]interface{},
	options ...DIDOption,
) (*DID, error) {
	cfg := d.resolveConfig(options...)

	// 1. Create Issuer Signature.
	issuerSig, err := d.CreateIssuerSignature(ctx, didType, keyPair.Address, WithDIDConfig(&cfg))
	if err != nil {
		return nil, fmt.Errorf("failed to create issuer signature: %w", err)
	}

	// 2. Generate DID Document.
	issuerAddress := cfg.SignerProvider.GetAddress()
	issuerDID := fmt.Sprintf("%s:%s", cfg.Method, issuerAddress)
	didDoc := GenerateDIDDocument(keyPair, didType, hash, metadata, issuerDID)
	docHash, err := didDoc.Hash()
	if err != nil {
		return nil, fmt.Errorf("failed to hash DID document: %w", err)
	}

	// 3. Create DID Tx Transaction.
	didTxSigner, err := signer.NewDefaultProvider(keyPair.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create tx signer: %w", err)
	}

	txResult, err := d.GenerateDIDTXFromIssuerSig(ctx, didType, didTxSigner, docHash, issuerSig, issuerAddress, WithDIDConfig(&cfg))
	if err != nil {
		return nil, fmt.Errorf("failed to generate DID TX from issuer signature: %w", err)
	}

	// 4. To did result.
	return &DID{
		DID:         keyPair.Identifier,
		Secret:      Secret{PrivateKeyHex: keyPair.PrivateKey},
		Document:    *didDoc,
		Transaction: *txResult,
	}, nil
}

// CreateIssuerSignature creates an issuer signature for a DID.
//
// issuer signature present issuer access to create did.
func (d *DIDGenerator) CreateIssuerSignature(ctx context.Context, didType blockchain.DIDType, didAddress string, options ...DIDOption) (*blockchain.Signature, error) {
	cfg := d.resolveConfig(options...)

	// issuer provider is required to sign the payload.
	if cfg.SignerProvider == nil {
		return nil, fmt.Errorf("signer provider is required to authorize creation")
	}

	if cfg.SyncEpoch {
		epoch, err := d.registry.GetCapabilityEpoch(ctx, cfg.SignerProvider.GetAddress())
		if err != nil {
			return nil, fmt.Errorf("failed to sync epoch: %w", err)
		}
		cfg.Epoch = epoch
	}

	issuerAddress := cfg.SignerProvider.GetAddress()
	smcAddress := common.HexToAddress(cfg.DIDSMCAddress)

	// create issuer signature payload to create did.
	payloadHash, err := ComputeDSOPayload(
		smcAddress,
		issuerAddress,
		didAddress,
		didType,
		cfg.CapID,
		cfg.Epoch,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to compute payload hash: %w", err)
	}

	sigBytes, err := cfg.SignerProvider.Sign(payloadHash)
	if err != nil {
		return nil, fmt.Errorf("failed to sign payload: %w", err)
	}

	issuerSig, err := signatureFromBytes(sigBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid signature format: %w", err)
	}

	return issuerSig, nil
}

// GenerateDIDTXFromIssuerSig generates a DID TX from an issuer signature.
func (d *DIDGenerator) GenerateDIDTXFromIssuerSig(
	ctx context.Context,
	didType blockchain.DIDType,
	didTxSigner signer.SignerProvider,
	docHash string,
	issuerSig *blockchain.Signature,
	issuerAddress string,
	options ...DIDOption,
) (*blockchain.SubmitTxResult, error) {
	cfg := d.resolveConfig(options...)

	if issuerSig == nil {
		return nil, fmt.Errorf("issuer signature is required")
	}

	if cfg.SyncNonce {
		nonce, err := d.registry.GetNonce(ctx, common.HexToAddress(didTxSigner.GetAddress()))
		if err != nil {
			return nil, fmt.Errorf("failed to sync nonce: %w", err)
		}
		cfg.Nonce = nonce
	}

	req := blockchain.CreateDIDRequest{
		IssuerSig:     issuerSig,
		IssuerAddress: issuerAddress,
		DocHash:       docHash,
		CapID:         cfg.CapID,
		TxProvider:    didTxSigner,
		DIDType:       didType,
		Nonce:         cfg.Nonce,
	}

	txResult, err := d.registry.CreateDIDTx(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("blockchain tx failed: %w", err)
	}

	return txResult, nil
}

func (d *DIDGenerator) GetCapabilityEpoch(ctx context.Context, address string) (uint64, error) {
	return d.registry.GetCapabilityEpoch(ctx, address)
}

func (d *DIDGenerator) GetNonce(ctx context.Context, address string) (uint64, error) {
	return d.registry.GetNonce(ctx, common.HexToAddress(address))
}

// resolveConfig merges run-time options with the base configuration.
func (d *DIDGenerator) resolveConfig(options ...DIDOption) DIDConfig {
	cfg := d.baseConfig
	for _, opt := range options {
		opt(&cfg)
	}

	if cfg.CapID == "" {
		hexStr, err := RandomHex(32)
		if err != nil {
			// Fallback (highly unlikely)
			cfg.CapID = "0x" + strings.Repeat("0", 64)
		} else {
			cfg.CapID = hexStr // RandomHex already adds "0x"
		}
	}
	return cfg
}
