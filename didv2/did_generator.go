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
		ChainID:       DefaultChainID,
		DIDSMCAddress: DefaultDIDSMCAddress,
		Method:        DefaultMethod,
	}

	for _, opt := range options {
		opt(&cfg)
	}

	if cfg.DIDSMCAddress == "" {
		return nil, fmt.Errorf("DID contract address is required")
	}

	clientCfg := blockchain.ClientConfig{
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

	return d.GenerateDIDTX(ctx, didType, keyPair, hash, metadata, options...)
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

	if cfg.SignerProvider == nil {
		return nil, fmt.Errorf("signer provider is required to authorize creation")
	}

	// 1. Prepare DID Document
	signerDID := fmt.Sprintf("%s:%s", cfg.Method, cfg.SignerProvider.GetAddress())
	doc := GenerateDIDDocument(keyPair, didType, hash, metadata, signerDID)
	docHash, err := doc.Hash()
	if err != nil {
		return nil, fmt.Errorf("failed to hash DID document: %w", err)
	}

	// 2. Create & Sign Payload
	payloadHash, err := computeDSOPayload(
		common.HexToAddress(cfg.DIDSMCAddress),
		cfg.SignerProvider.GetAddress(),
		keyPair.Address,
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

	// 3. Submit Transaction
	txProvider, err := signer.NewDefaultProvider(keyPair.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create tx provider: %w", err)
	}

	req := blockchain.CreateDIDRequest{
		IssuerSig:     issuerSig,
		IssuerAddress: cfg.SignerProvider.GetAddress(),
		DocHash:       docHash,
		CapID:         cfg.CapID,
		TxProvider:    txProvider,
		DIDType:       didType,
		Nonce:         cfg.Nonce,
	}

	txResult, err := d.registry.CreateDIDTx(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("blockchain tx failed: %w", err)
	}

	return &DID{
		DID:         keyPair.Identifier,
		Secret:      Secret{PrivateKeyHex: keyPair.PrivateKey},
		Document:    *doc,
		Transaction: *txResult,
	}, nil
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
