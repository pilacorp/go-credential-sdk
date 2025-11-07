package did

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/pilacorp/go-did-sdk/blockchain"
)

// DIDChain represents the configuration for interacting with the Ethereum DID Registry
type DIDGenerator struct {
	didMethod string
}

// TODO: Move to Package config level
const (
	RPC        = "https://rpc-testnet.pila.vn"
	ChainID    = 6789
	DIDAddress = "0x0000000000000000000000000000000000018888"
)

// NewDIDChain initializes a new DIDChain instance
func NewDIDGenerator(method string) *DIDGenerator {
	return &DIDGenerator{
		didMethod: method,
	}
}

func (d *DIDGenerator) GenerateDID(ctx context.Context, newDID CreateDID) (*DID, error) {
	// Generate a new private key
	did, err := d.generateECDSADID()
	if err != nil {
		return nil, err
	}
	// Create DID document
	doc := d.generateDIDDocument(did, &newDID)

	didRegistry, err := blockchain.NewEthereumDIDRegistry(RPC, DIDAddress, ChainID)
	if err != nil {
		return nil, err
	}
	tx, err := didRegistry.GenerateSetAttributeTx(ctx, did.PrivateKey, did.Identifier, string(newDID.Type))
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

func (d *DIDGenerator) generateECDSADID() (*KeyPair, error) {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	publicKeyECDSA, ok := privateKey.Public().(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("-----error casting public key to ECDSA")
	}
	address := strings.ToLower(crypto.PubkeyToAddress(*publicKeyECDSA).Hex())
	privateKeyHex := strings.ToLower("0x" + fmt.Sprintf("%x", crypto.FromECDSA(privateKey)))
	publicKeyHex := strings.ToLower("0x" + fmt.Sprintf("%x", crypto.CompressPubkey(publicKeyECDSA)))

	// Create DID identifier: ${method}:${address}
	identifier := strings.ToLower(fmt.Sprintf("%s:%s", d.didMethod, address))

	// Create KeyPair
	keyPair := &KeyPair{
		Address:    address,
		PublicKey:  publicKeyHex,
		PrivateKey: privateKeyHex,
		Identifier: identifier,
	}

	return keyPair, nil
}

func (d *DIDGenerator) generateDIDDocument(did *KeyPair, didReq *CreateDID) *DIDDocument {
	document := &DIDDocument{
		Context: []string{"https://w3id.org/security/v1",
			"https://www.w3.org/ns/did/v1"},
		Id:         did.Identifier,
		Controller: did.Identifier,
		VerificationMethod: []VerificationMethod{{
			Id:           did.Identifier + "#key-1",
			Type:         "EcdsaSecp256k1VerificationKey2019",
			Controller:   did.Identifier,
			PublicKeyHex: did.PublicKey,
		}},
		Authentication:   []string{did.Identifier + "#key-1"},
		AssertionMethod:  []string{did.Identifier + "#key-1"},
		DocumentMetadata: didReq.Metadata,
	}
	if document.DocumentMetadata == nil {
		document.DocumentMetadata = map[string]interface{}{
			"type": didReq.Type,
			"hash": didReq.Hash,
		}
	} else {
		document.DocumentMetadata["type"] = didReq.Type
		document.DocumentMetadata["hash"] = didReq.Hash
	}

	return document
}
