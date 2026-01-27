package didcontract

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/pilacorp/go-credential-sdk/didv2/did"
	"github.com/pilacorp/go-credential-sdk/didv2/issuer"
)

const DefaultGasLimit = 200000.

// defaultGasPrice is 0 for chain with gas-free.
var defaultGasPrice = big.NewInt(0)

// Config holds configuration for the DIDContract client.
type Config struct {
	RPCURL          string
	ContractAddress string
	ChainID         int64
	GasPrice        *big.Int
	GasLimit        uint64
}

// CreateDIDRequest is the request for the CreateDIDTx.
type CreateDIDRequest struct {
	IssuerAddress string
	IssuerSig     *issuer.Signature
	DocHash       string
	CapID         string
	DIDType       did.DIDType
	Nonce         uint64
}

// Transaction is the result of the CreateDIDTx.
type Transaction struct {
	TxHex  string
	TxHash string
}

// Validate validates the config.
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

// Standardize standardizes the config.
func (c *Config) Standardize() {
	if c.GasLimit == 0 {
		c.GasLimit = DefaultGasLimit
	}

	if c.GasPrice == nil {
		c.GasPrice = defaultGasPrice
	}
}
