package blockchain

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

// MaxAttributeNameLength defines the maximum length for attribute names (32 bytes).
const (
	MaxAttributeNameLength   = 32
	AttributeValiditySeconds = 86400
)

func ParsePrivateKey(key string) (*ecdsa.PrivateKey, error) {
	key = strings.TrimPrefix(key, "0x")
	if len(key) == 0 || len(key)%2 != 0 {
		return nil, fmt.Errorf("invalid private key: empty or odd length")
	}
	privKey, err := crypto.HexToECDSA(key)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}
	return privKey, nil
}

// prepareAttributeInputs validates and converts inputs for the SetAttribute call.
// It now accepts a *big.Int for validity.
func PrepareAttributeInputs(address, name, value string) (common.Address, [32]byte, []byte, *big.Int, error) {
	// Validate inputs
	if address == "" {
		return common.Address{}, [32]byte{}, nil, nil, fmt.Errorf("identity is empty")
	}
	if name == "" {
		return common.Address{}, [32]byte{}, nil, nil, fmt.Errorf("name is empty")
	}
	if len(name) > MaxAttributeNameLength {
		return common.Address{}, [32]byte{}, nil, nil, fmt.Errorf("name exceeds %d bytes", MaxAttributeNameLength)
	}

	// Convert identity to address
	didAddress := common.HexToAddress(strings.TrimPrefix(address, "0x"))

	// Convert name to fixed-size byte array
	var nameBytes [32]byte
	copy(nameBytes[:], name)

	// Convert value to bytes
	valueBytes := []byte(value)
	// Set validity
	validity := big.NewInt(AttributeValiditySeconds)

	// Validity is passed in, so we just return
	return didAddress, nameBytes, valueBytes, validity, nil
}

func TxFromHex(rawTxHex string) (*types.Transaction, error) {
	b, err := hex.DecodeString(rawTxHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex string: %w", err)
	}
	var tx types.Transaction
	if err := rlp.DecodeBytes(b, &tx); err != nil {
		return nil, fmt.Errorf("failed to decode RLP: %w", err)
	}
	return &tx, nil
}
