package didcontract

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/pilacorp/go-credential-sdk/didv2/did"
	"github.com/pilacorp/go-credential-sdk/didv2/issuer"
)

// DefaultGasLimit is the default gas limit for DID creation transactions.
const DefaultGasLimit = 200000

// defaultGasPrice is 0 for gas-free chains.
var defaultGasPrice = big.NewInt(0)

// Config holds configuration for the DIDContract client.
//
// The RPCURL is optional but required for read operations (GetCapabilityEpoch, GetNonce).
// If not provided, transaction creation can still work with manual nonce/epoch values.
type Config struct {
	// RPCURL is the blockchain RPC endpoint URL for network connectivity.
	// Optional but required for read operations.
	RPCURL string
	// ContractAddress is the address of the DID Registry smart contract.
	// Required and must be a valid hex address.
	ContractAddress string
	// ChainID is the blockchain network chain ID.
	// Required and must be greater than 0.
	ChainID int64
	// GasPrice is the gas price for transactions (in wei).
	// Defaults to 0 for gas-free chains.
	GasPrice *big.Int
	// GasLimit is the gas limit for transactions.
	// Defaults to DefaultGasLimit if not set.
	GasLimit uint64
}

// CreateDIDRequest contains all the data needed to create a DID creation transaction.
//
// This request is used by CreateDIDTx to build and sign a transaction for on-chain DID creation.
type CreateDIDRequest struct {
	// IssuerAddress is the Ethereum address of the Issuer who authorized this DID.
	IssuerAddress string
	// IssuerSig is the issuer signature proving authorization for DID creation.
	IssuerSig *issuer.Signature
	// DocHash is the Keccak256 hash of the canonicalized DID Document.
	// This binds the transaction to the specific document content.
	DocHash string
	// CapID is the capability ID for this specific DID issuance.
	CapID string
	// DIDType specifies the type of DID (People, Item, Location, Activity).
	DIDType did.DIDType
	// Nonce is the transaction nonce for the DID signer account.
	// Must be the current nonce from the blockchain or manually set.
	Nonce uint64
}

// Transaction represents a signed raw transaction ready for blockchain submission.
//
// The SDK creates this transaction but does not submit it. The TxHex must be
// submitted to the blockchain using a Web3 client, API, or other submission method.
type Transaction struct {
	// TxHex is the raw transaction in hex format, ready for blockchain submission.
	// This is the value to send via eth_sendRawTransaction RPC call.
	TxHex string
	// TxHash is the Keccak256 hash of the transaction, used as the transaction identifier.
	TxHash string
}

// Validate validates the Config to ensure required fields are present and valid.
//
// Checks:
//   - ContractAddress is a valid hex address (required)
//   - ChainID is greater than 0 (required)
//   - RPCURL is optional but a warning is printed if missing
//
// Returns an error if validation fails.
func (c *Config) Validate() error {
	if c.RPCURL == "" {
		fmt.Println("missing RPC URL, some features may not work")
	}

	if !common.IsHexAddress(c.ContractAddress) {
		return errors.New("contract address is required")
	}

	if c.ChainID <= 0 {
		return errors.New("chain ID must be greater than 0, it's required")
	}

	return nil
}

// Standardize sets default values for optional Config fields.
//
// Sets:
//   - GasLimit to DefaultGasLimit if not set
//   - GasPrice to 0 (gas-free) if not set
func (c *Config) Standardize() {
	if c.GasLimit == 0 {
		c.GasLimit = DefaultGasLimit
	}

	if c.GasPrice == nil {
		c.GasPrice = defaultGasPrice
	}
}
