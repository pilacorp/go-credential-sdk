package config

import (
	"os"
	"strconv"
)

// Default values
const (
	DefaultRPC        = "https://rpc-testnet.pila.vn"
	DefaultChainID    = 6789
	DefaultDIDAddress = "0x0000000000000000000000000000000000018888"
)

// Environment variable names
const (
	EnvRPC        = "DID_RPC_URL"
	EnvChainID    = "DID_CHAIN_ID"
	EnvDIDAddress = "DID_CONTRACT_ADDRESS"
)

// RPC returns the RPC URL from environment variable or default value
func RPC() string {
	if rpc := os.Getenv(EnvRPC); rpc != "" {
		return rpc
	}
	return DefaultRPC
}

// ChainID returns the Chain ID from environment variable or default value
func ChainID() int64 {
	if chainIDStr := os.Getenv(EnvChainID); chainIDStr != "" {
		if chainID, err := strconv.ParseInt(chainIDStr, 10, 64); err == nil {
			return chainID
		}
	}
	return DefaultChainID
}

// DIDAddress returns the DID contract address from environment variable or default value
func DIDAddress() string {
	if addr := os.Getenv(EnvDIDAddress); addr != "" {
		return addr
	}
	return DefaultDIDAddress
}
