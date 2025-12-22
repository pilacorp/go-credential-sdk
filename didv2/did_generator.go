package didv2

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/pilacorp/go-credential-sdk/didv2/blockchain"
	"github.com/pilacorp/go-credential-sdk/didv2/signer"
)

const (
	defaultChainID    = int64(6789)
	defaultDIDAddress = "0x0000000000000000000000000000000000018888"
	defaultMethod     = "did:nda"
)

// DIDGenerator handles DID generation and transaction creation
type DIDGenerator struct {
	chainID    int64
	didAddress string
	method     string
	registry   *blockchain.EthereumDIDRegistry
}

// NewDIDGenerator creates a new DIDGenerator with default values
func NewDIDGenerator(chainID int64, didAddress string, method string) (*DIDGenerator, error) {
	g := &DIDGenerator{
		chainID:    defaultChainID,
		didAddress: defaultDIDAddress,
		method:     defaultMethod,
	}

	if chainID != 0 {
		g.chainID = chainID
	}
	if didAddress != "" {
		g.didAddress = didAddress
	}
	if method != "" {
		g.method = method
	}

	registry, err := blockchain.NewEthereumDIDRegistry(g.didAddress, g.chainID)
	if err != nil {
		return nil, fmt.Errorf("failed to create registry: %w", err)
	}
	g.registry = registry

	return g, nil
}

// GenerateDID generates a new DID with a newly created key pair
func (d *DIDGenerator) GenerateDID(
	ctx context.Context,
	sigSigner signer.Signer,
	issuerAddress string,
	didType blockchain.DIDType,
	hash string,
	deadline uint,
	metadata map[string]interface{},
) (*DID, error) {
	// 1. Generate a new key pair
	keyPair, err := d.generateECDSADID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	// 2. Generate DID document
	doc := d.generateDIDDocument(keyPair, didType, hash, metadata)

	// Calculate document hash (TODO: correct the implementation)
	docHash, err := doc.Hash()
	if err != nil {
		return nil, fmt.Errorf("failed to hash DID document: %w", err)
	}

	// 3. Create payload to sign using document hash
	payload, err := d.registry.IssueDIDPayload(issuerAddress, keyPair.Address, docHash, didType, deadline)
	if err != nil {
		return nil, fmt.Errorf("failed to create payload: %w", err)
	}

	// 4. Sign the payload using the sigSigner
	signatureBytes, err := sigSigner.Sign(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to sign payload: %w", err)
	}

	// Convert signature bytes to signature object
	signature, err := blockchain.BytesToSignature(signatureBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to convert signature: %w", err)
	}

	// 5. Create DID transaction
	// keyPair.PrivateKey is stored with "0x" prefix; HexToECDSA expects raw hex.
	privHex := strings.TrimPrefix(keyPair.PrivateKey, "0x")
	txSigner, err := signer.NewDefaultSigner(privHex)
	if err != nil {
		return nil, fmt.Errorf("failed to create tx signer: %w", err)
	}

	txResult, err := d.registry.CreateDIDTx(ctx, signature, issuerAddress, keyPair.Address, docHash, txSigner, didType, deadline)
	if err != nil {
		return nil, fmt.Errorf("failed to create DID transaction: %w", err)
	}

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
	identifier := strings.ToLower(fmt.Sprintf("%s:%s", d.method, address))

	return &KeyPair{
		Address:    address,
		PublicKey:  publicKeyHex,
		PrivateKey: privateKeyHex,
		Identifier: identifier,
	}, nil
}

// didTypeToString converts blockchain.DIDType to string representation
func (d *DIDGenerator) didTypeToString(didType blockchain.DIDType) string {
	switch didType {
	case blockchain.DIDTypePeople:
		return "people"
	case blockchain.DIDTypeItem:
		return "item"
	case blockchain.DIDTypeActivity:
		return "activity"
	case blockchain.DIDTypeLocation:
		return "location"
	default:
		return "default"
	}
}

// generateDIDDocument creates a DID document from a key pair and request metadata
func (d *DIDGenerator) generateDIDDocument(keyPair *KeyPair, didType blockchain.DIDType, hash string, metadata map[string]interface{}) *DIDDocument {
	docMetadata := make(map[string]interface{})

	// Copy existing metadata if present
	for k, v := range metadata {
		docMetadata[k] = v
	}

	// Always set type and hash
	docMetadata["type"] = d.didTypeToString(didType)
	docMetadata["hash"] = hash

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
		DocumentMetadata: docMetadata,
	}

	return document
}
