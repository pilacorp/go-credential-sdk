package did

import (
	"context"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/pilacorp/go-credential-sdk/did/blockchain"
	"github.com/pilacorp/go-credential-sdk/did/config"
)

// DIDChain represents the configuration for interacting with the Ethereum DID Registry
type DIDGenerator struct {
	config config.Config
}
type Option func(*DIDGenerator)

// WithConfig sets the configuration for the DIDGenerator.
func WithConfig(c config.Config) Option {
	return func(g *DIDGenerator) {
		g.config = c
	}
}

// NewDIDChain initializes a new DIDChain instance
func NewDIDGenerator(options ...Option) *DIDGenerator {
	g := &DIDGenerator{
		config: *config.New(config.Config{}), // The zero-value or a "default"
	}

	// 2. Loop over all provided options and apply them
	for _, opt := range options {
		opt(g)
	}

	// 3. Return the configured generator
	return g
}

func (d *DIDGenerator) GenerateDID(ctx context.Context, newDID CreateDID) (*DID, error) {
	// Generate a new private key
	did, err := generateECDSADID(d.config.Method)
	if err != nil {
		return nil, err
	}
	// Create DID document
	doc := generateDIDDocument(
		did,
		newDID.Type,
		newDID.Hash,
		newDID.Metadata,
		did.Identifier,
	)

	didRegistry, err := blockchain.NewEthereumDIDRegistry(d.config.RPC, d.config.DIDAddress, d.config.ChainID)
	if err != nil {
		return nil, err
	}
	tx, err := didRegistry.GenerateSetAttributeTx(ctx, did.PrivateKey, did.Address, string(newDID.Type))
	if err != nil {
		return nil, err
	}

	createdDID := DID{
		DID: did.Identifier,
		Secret: Secret{
			PrivateKeyHex: did.PrivateKey,
		},
		Document:    *doc,
		Transaction: *tx,
	}

	return &createdDID, nil
}

func (d *DIDGenerator) ReGenerateDIDTX(ctx context.Context, privKey string, didMetadata map[string]interface{}) (*blockchain.SubmitDIDTX, error) {

	privHexString := strings.TrimPrefix(privKey, "0x")
	privateKey, err := crypto.HexToECDSA(privHexString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}
	publicKey := privateKey.PublicKey
	address := crypto.PubkeyToAddress(publicKey).Hex()

	if value, ok := didMetadata["type"]; !ok || value == "" {
		return nil, fmt.Errorf("did type is required")
	}

	didRegistry, err := blockchain.NewEthereumDIDRegistry(d.config.RPC, d.config.DIDAddress, d.config.ChainID)
	if err != nil {
		return nil, err
	}

	newTx, err := didRegistry.GenerateSetAttributeTx(ctx, privKey, address, fmt.Sprintf("%v", (didMetadata["type"])))
	if err != nil {
		return newTx, err
	}

	return newTx, nil
}
