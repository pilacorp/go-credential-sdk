package didv2

import (
	"context"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/pilacorp/go-credential-sdk/didv2/blockchain"
	"github.com/pilacorp/go-credential-sdk/didv2/signer"
)

const (
	defaultRPC        = "https://rpc-testnet-new.pila.vn"
	defaultChainID    = int64(704)
	defaultDIDAddress = "0x75e7b09a24bCE5a921bABE27b62ec7bfE2230d6A"
	defaultMethod     = "did:nda"
	defaultEpoch      = uint64(0)
)

type DIDConfig struct {
	RPC            string
	ChainID        int64
	DIDAddress     string
	Method         string
	SignerProvider signer.SignerProvider
	Epoch          uint64 // optional, default 0
	CapID          string // optional, auto-generated random hex if not provided
}

type DIDOption func(*DIDConfig)

func WithRPCV2(rpc string) DIDOption {
	return func(c *DIDConfig) {
		c.RPC = rpc
	}
}

func WithDIDChainID(chainID int64) DIDOption {
	return func(c *DIDConfig) {
		c.ChainID = chainID
	}
}

func WithDIDAddressSMC(didAddress string) DIDOption {
	return func(c *DIDConfig) {
		c.DIDAddress = didAddress
	}
}

func WithMethod(method string) DIDOption {
	return func(c *DIDConfig) {
		c.Method = method
	}
}

func WithEpoch(epoch uint64) DIDOption {
	return func(c *DIDConfig) {
		c.Epoch = epoch
	}
}

func WithSignerProvider(signerProvider signer.SignerProvider) DIDOption {
	return func(c *DIDConfig) {
		c.SignerProvider = signerProvider
	}
}

func WithDIDConfig(config *DIDConfig) DIDOption {
	return func(c *DIDConfig) {
		c.RPC = config.RPC
		c.ChainID = config.ChainID
		c.DIDAddress = config.DIDAddress
		c.Method = config.Method
	}
}

// DIDGenerator handles DID generation and transaction creation
type DIDGenerator struct {
	chainID         int64
	contractAddress string
	method          string
	registry        *blockchain.DIDContract
	defaultProvider signer.SignerProvider
}

// NewDIDGenerator creates a new DIDGenerator with default values
func NewDIDGenerator(options ...DIDOption) (*DIDGenerator, error) {
	d := &DIDGenerator{}

	config := d.executeOptions(options...)

	registry, err := blockchain.NewDIDContract(config.DIDAddress, config.ChainID, config.RPC)
	if err != nil {
		return nil, fmt.Errorf("failed to create registry: %w", err)
	}

	return &DIDGenerator{
		chainID:         config.ChainID,
		contractAddress: config.DIDAddress,
		method:          config.Method,
		registry:        registry,
		defaultProvider: config.SignerProvider,
	}, nil
}

// GenerateDID generates a new DID with a newly created key pair
func (d *DIDGenerator) GenerateDID(
	ctx context.Context,
	didType blockchain.DIDType,
	hash string,
	metadata map[string]interface{},
	options ...DIDOption,
) (*DID, error) {
	config := d.executeOptions(options...)
	// Generate a new key pair (this DID will be msg.sender on-chain)
	keyPair, err := generateECDSADID(config.Method)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	return d.ReGenerateDID(ctx, didType, keyPair, hash, metadata, options...)
}

// ReGenerateDID generates a createDID transaction for existing DID
func (d *DIDGenerator) ReGenerateDID(
	ctx context.Context,
	didType blockchain.DIDType,
	keyPair *KeyPair,
	hash string,
	metadata map[string]interface{},
	options ...DIDOption,
) (*DID, error) {
	config := d.executeOptions(options...)

	signerDID := fmt.Sprintf("%s:%s", config.Method, config.SignerProvider.GetAddress())
	
	// 1. Generate DID document
	doc := generateDIDDocument(keyPair, didType, hash, metadata, signerDID)

	// 2. Calculate document hash
	docHash, err := doc.Hash()
	if err != nil {
		return nil, fmt.Errorf("failed to hash DID document: %w", err)
	}

	// 3. Create payload to sign for _requireValidCapCreate(...)
	parts := strings.Split(signerDID, ":")
	signerAddress := parts[len(parts)-1]

	payload, err := d.registry.IssueDIDPayload(
		ctx,
		signerAddress,
		keyPair.Address, // did (msg.sender)
		didType,
		config.CapID,
		config.Epoch,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create payload: %w", err)
	}

	hashPayload := crypto.Keccak256(payload)

	// 4. Sign the payload using sigSigner (this becomes v,r,s)
	signatureBytes, err := config.SignerProvider.Sign(hashPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to sign payload: %w", err)
	}

	signature, err := blockchain.BytesToSignature(signatureBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to convert signature: %w", err)
	}

	// 5. Create transaction signer for msg.sender (the DID keypair)
	txProvider, err := signer.NewDefaultProvider(keyPair.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create tx provider: %w", err)
	}

	// 6. Create DID transaction (matches new createDID signature)
	txResult, err := d.registry.CreateDIDTx(
		ctx,
		signature,
		keyPair.Address, // msg.sender (did)
		docHash,
		config.CapID,
		txProvider,
		didType,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create DID transaction: %w", err)
	}

	return &DID{
		DID: keyPair.Identifier,
		Secret: Secret{
			PrivateKeyHex: keyPair.PrivateKey,
		},
		Document: *doc,
		Transaction: blockchain.SubmitTxResult{
			TxHex:  txResult.TxHex,
			TxHash: txResult.TxHash,
		},
	}, nil
}

// GetSignerEpoch gets the capability epoch of a signer
func (d *DIDGenerator) GetCapabilityEpoch(ctx context.Context, signerAddress string) (uint64, error) {
	return d.registry.GetCapabilityEpoch(ctx, signerAddress)
}

func (d *DIDGenerator) executeOptions(options ...DIDOption) *DIDConfig {
	capID, err := RandomHex(32)
	if err != nil {
		panic(fmt.Errorf("failed to generate cap id: %w", err))
	}

	config := &DIDConfig{
		RPC:        defaultRPC,
		ChainID:    defaultChainID,
		DIDAddress: defaultDIDAddress,
		Method:     defaultMethod,
		Epoch:      defaultEpoch,
		CapID:      capID,
	}

	for _, opt := range options {
		opt(config)
	}

	if config.SignerProvider == nil {
		config.SignerProvider = d.defaultProvider
	}

	return config
}
