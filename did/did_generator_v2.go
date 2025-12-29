package did

import (
	"context"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/pilacorp/go-credential-sdk/did/blockchain"
	"github.com/pilacorp/go-credential-sdk/did/signer"
)

const (
	defaultRPCV2        = "https://rpc-testnet-new.pila.vn"
	defaultChainIDV2    = int64(704)
	defaultDIDAddressV2 = "0x75e7b09a24bCE5a921bABE27b62ec7bfE2230d6A"
	defaultMethodV2     = "did:nda"
	defaultEpochV2      = uint64(0)
)

type ConfigV2 struct {
	RPC        string
	ChainID    int64
	DIDAddress string
	Method     string
	Epoch      uint64
	CapID      string
}

type OptionV2 func(*ConfigV2)

func WithRPCV2(rpc string) OptionV2 {
	return func(c *ConfigV2) {
		c.RPC = rpc
	}
}

func WithChainIDV2(chainID int64) OptionV2 {
	return func(c *ConfigV2) {
		c.ChainID = chainID
	}
}

func WithDIDAddressV2(didAddress string) OptionV2 {
	return func(c *ConfigV2) {
		c.DIDAddress = didAddress
	}
}

func WithMethodV2(method string) OptionV2 {
	return func(c *ConfigV2) {
		c.Method = method
	}
}

func WithEpochV2(epoch uint64) OptionV2 {
	return func(c *ConfigV2) {
		c.Epoch = epoch
	}
}

func WithConfigV2(config *ConfigV2) OptionV2 {
	return func(c *ConfigV2) {
		c.RPC = config.RPC
		c.ChainID = config.ChainID
		c.DIDAddress = config.DIDAddress
		c.Method = config.Method
		c.Epoch = config.Epoch
	}
}

// DIDGenerator handles DID generation and transaction creation
type DIDGeneratorV2 struct {
	chainID         int64
	contractAddress string
	method          string
	registry        *blockchain.DIDContract
}

// NewDIDGenerator creates a new DIDGenerator with default values
func NewDIDGeneratorV2(options ...OptionV2) (*DIDGeneratorV2, error) {
	configV2 := executeOptionsV2(options...)

	registry, err := blockchain.NewDIDContract(configV2.DIDAddress, configV2.ChainID, configV2.RPC)
	if err != nil {
		return nil, fmt.Errorf("failed to create registry: %w", err)
	}

	return &DIDGeneratorV2{
		chainID:         configV2.ChainID,
		contractAddress: configV2.DIDAddress,
		method:          configV2.Method,
		registry:        registry,
	}, nil
}

// GenerateDID generates a new DID with a newly created key pair
func (d *DIDGeneratorV2) GenerateDID(
	ctx context.Context,
	sigSigner signer.Signer, // signs the cap payload (signer in SMC)
	signerDID string, // address param "signer" in createDID(...)
	didType blockchain.DIDType,
	hash string,
	metadata map[string]interface{},
	options ...OptionV2,
) (*DID, error) {
	configV2 := executeOptionsV2(options...)

	// 1. Generate a new key pair (this DID will be msg.sender on-chain)
	keyPair, err := generateECDSADID(configV2.Method)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	// 2. Generate DID document
	doc := generateDIDDocument(keyPair, didType, hash, metadata, signerDID)

	// 3. Calculate document hash
	docHash, err := doc.Hash()
	if err != nil {
		return nil, fmt.Errorf("failed to hash DID document: %w", err)
	}

	// 4. Create payload to sign for _requireValidCapCreate(...)
	parts := strings.Split(signerDID, ":")
	signerAddress := parts[len(parts)-1]

	payload, err := d.registry.IssueDIDPayload(
		ctx,
		signerAddress,
		keyPair.Address, // did (msg.sender)
		didType,
		configV2.CapID,
		configV2.Epoch,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create payload: %w", err)
	}

	hashPayload := crypto.Keccak256(payload)

	// 5. Sign the payload using sigSigner (this becomes v,r,s)
	signatureBytes, err := sigSigner.Sign(hashPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to sign payload: %w", err)
	}

	signature, err := blockchain.BytesToSignature(signatureBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to convert signature: %w", err)
	}

	// 6. Create transaction signer for msg.sender (the DID keypair)
	txSigner, err := signer.NewDefaultSigner(keyPair.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create tx signer: %w", err)
	}

	// 7. Create DID transaction (matches new createDID signature)
	txResult, err := d.registry.CreateDIDTx(
		ctx,
		signature,
		signerAddress,   // signer param
		keyPair.Address, // msg.sender (did)
		docHash,
		configV2.CapID,
		txSigner,
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
		Transaction: blockchain.SubmitDIDTX{
			TxHex:  txResult.TxHex,
			TxHash: txResult.TxHash,
		},
	}, nil
}

// GetSignerEpoch gets the capability epoch of a signer
func (d *DIDGeneratorV2) GetCapabilityEpoch(ctx context.Context, signerAddress string) (uint64, error) {
	return d.registry.GetCapabilityEpoch(ctx, signerAddress)
}

func executeOptionsV2(options ...OptionV2) *ConfigV2 {
	capId, err := RandomHex(32)
	if err != nil {
		panic(fmt.Errorf("failed to generate cap id: %w", err))
	}

	configV2 := &ConfigV2{
		RPC:        defaultRPCV2,
		ChainID:    defaultChainIDV2,
		DIDAddress: defaultDIDAddressV2,
		Method:     defaultMethodV2,
		Epoch:      defaultEpochV2,
		CapID:      capId,
	}

	for _, opt := range options {
		opt(configV2)
	}

	return configV2
}
