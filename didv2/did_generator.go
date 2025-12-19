package didv2

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/pilacorp/go-credential-sdk/didv2/blockchain"
	"github.com/pilacorp/go-credential-sdk/didv2/config"
)

// DIDGenerator handles DID generation and transaction creation
type DIDGenerator struct {
	config config.Config
}

// Option configures a DIDGenerator
type Option func(*DIDGenerator)

// WithConfig sets the configuration for the DIDGenerator
func WithConfig(c config.Config) Option {
	return func(g *DIDGenerator) {
		g.config = c
	}
}

// NewDIDGenerator creates a new DIDGenerator instance with the provided options
func NewDIDGenerator(options ...Option) *DIDGenerator {
	g := &DIDGenerator{
		config: *config.New(config.Config{}),
	}

	for _, opt := range options {
		opt(g)
	}

	return g
}

// GenerateDID generates a new DID with a newly created key pair
func (d *DIDGenerator) GenerateDID(ctx context.Context, req CreateDID) (*DID, error) {
	// Generate a new key pair
	keyPair, err := d.generateECDSADID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	// Create registry client
	registry, err := blockchain.NewEthereumDIDRegistry(d.config.DIDAddress, d.config.ChainID)
	if err != nil {
		return nil, fmt.Errorf("failed to create registry: %w", err)
	}

	// Create issuer signature
	signature, err := d.createIssuerSignature(registry, req.IssuerAddress, req.IssuerPkHex, keyPair.Address, req.Hash, req.Type, req.Deadline)
	if err != nil {
		return nil, fmt.Errorf("failed to create issuer signature: %w", err)
	}

	// Create DID transaction
	txResult, err := registry.CreateDIDTx(ctx, signature, req.IssuerAddress, keyPair.PrivateKey, keyPair.Address, req.Hash, req.Type, req.Deadline)
	if err != nil {
		return nil, fmt.Errorf("failed to create DID transaction: %w", err)
	}

	// Generate DID document
	doc := d.generateDIDDocument(keyPair, &req)

	return &DID{
		DID: keyPair.Identifier,
		Secret: Secret{
			PrivateKeyHex: keyPair.PrivateKey,
		},
		Document: doc,
		Transaction: &blockchain.SubmitTxResult{
			TxHex:  txResult.TxHex,
			TxHash: txResult.TxHash,
		},
	}, nil
}

// ReGenerateDIDTx regenerates a DID transaction using an existing private key
func (d *DIDGenerator) ReGenerateDIDTx(ctx context.Context, req ReGenerateDIDRxRequest) (*blockchain.SubmitTxResult, error) {
	// Derive key pair from existing private key
	keyPair, err := d.deriveKeyPairFromPrivateKey(req.DIDPkHex)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key pair: %w", err)
	}

	// Create registry client
	registry, err := blockchain.NewEthereumDIDRegistry(d.config.DIDAddress, d.config.ChainID)
	if err != nil {
		return nil, fmt.Errorf("failed to create registry: %w", err)
	}

	// Create issuer signature
	signature, err := d.createIssuerSignature(registry, req.IssuerAddress, req.IssuerPkHex, keyPair.Address, req.Hash, req.Type, req.Deadline)
	if err != nil {
		return nil, fmt.Errorf("failed to create issuer signature: %w", err)
	}

	// Create DID transaction
	txResult, err := registry.CreateDIDTx(ctx, signature, req.IssuerAddress, req.DIDPkHex, keyPair.Address, req.Hash, req.Type, req.Deadline)
	if err != nil {
		return nil, fmt.Errorf("failed to create DID transaction: %w", err)
	}

	return txResult, nil
}

// createIssuerSignature creates and signs the issuer payload for DID creation
func (d *DIDGenerator) createIssuerSignature(
	registry *blockchain.EthereumDIDRegistry,
	issuerAddress, issuerPkHex, didAddress, docHash string,
	didType blockchain.DIDType,
	deadline uint,
) (*blockchain.Signature, error) {
	// Create payload
	payload, err := registry.IssueDIDPayload(issuerAddress, didAddress, docHash, didType, deadline)
	if err != nil {
		return nil, fmt.Errorf("failed to create payload: %w", err)
	}

	// Parse issuer private key
	issuerKey, err := blockchain.ParsePrivateKey(issuerPkHex)
	if err != nil {
		return nil, fmt.Errorf("failed to parse issuer private key: %w", err)
	}

	// Sign payload
	signatureBytes, err := blockchain.SignPayload(issuerKey, payload)
	if err != nil {
		return nil, fmt.Errorf("failed to sign payload: %w", err)
	}

	// Convert to signature object
	signature, err := blockchain.BytesToSignature(signatureBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to convert signature: %w", err)
	}

	return signature, nil
}

// generateECDSADID generates a new ECDSA key pair and creates a KeyPair
func (d *DIDGenerator) generateECDSADID() (*KeyPair, error) {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	return d.createKeyPairFromECDSA(privateKey)
}

// deriveKeyPairFromPrivateKey derives a KeyPair from an existing private key hex string
func (d *DIDGenerator) deriveKeyPairFromPrivateKey(privateKeyHex string) (*KeyPair, error) {
	privateKey, err := blockchain.ParsePrivateKey(privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return d.createKeyPairFromECDSA(privateKey)
}

// createKeyPairFromECDSA creates a KeyPair from an ECDSA private key
func (d *DIDGenerator) createKeyPairFromECDSA(privateKey *ecdsa.PrivateKey) (*KeyPair, error) {
	publicKeyECDSA, ok := privateKey.Public().(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("failed to cast public key to ECDSA")
	}

	address := strings.ToLower(crypto.PubkeyToAddress(*publicKeyECDSA).Hex())
	privateKeyHex := strings.ToLower("0x" + fmt.Sprintf("%x", crypto.FromECDSA(privateKey)))
	publicKeyHex := strings.ToLower("0x" + fmt.Sprintf("%x", crypto.CompressPubkey(publicKeyECDSA)))
	identifier := strings.ToLower(fmt.Sprintf("%s:%s", d.config.Method, address))

	return &KeyPair{
		Address:    address,
		PublicKey:  publicKeyHex,
		PrivateKey: privateKeyHex,
		Identifier: identifier,
	}, nil
}

// generateDIDDocument creates a DID document from a key pair and request metadata
func (d *DIDGenerator) generateDIDDocument(keyPair *KeyPair, req *CreateDID) *DIDDocument {
	metadata := make(map[string]interface{})

	// Copy existing metadata if present
	if req.Metadata != nil {
		for k, v := range req.Metadata {
			metadata[k] = v
		}
	}

	// Always set type and hash
	metadata["type"] = req.Type
	metadata["hash"] = req.Hash

	document := &DIDDocument{
		Context: []string{
			"https://w3id.org/security/v1",
			"https://www.w3.org/ns/did/v1",
		},
		Id:         keyPair.Identifier,
		Controller: keyPair.Identifier,
		VerificationMethod: []VerificationMethod{{
			Id:           keyPair.Identifier + "#key-1",
			Type:         "EcdsaSecp256k1VerificationKey2019",
			Controller:   keyPair.Identifier,
			PublicKeyHex: keyPair.PublicKey,
		}},
		Authentication:   []string{keyPair.Identifier + "#key-1"},
		AssertionMethod:  []string{keyPair.Identifier + "#key-1"},
		DocumentMetadata: metadata,
	}

	return document
}
