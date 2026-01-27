package didv2

import (
	"strings"

	"github.com/pilacorp/go-credential-sdk/didv2/signer"
)

// Default configuration constants for the DID V2 SDK.
//
// These values can be overridden using configuration options when creating
// a DIDGenerator instance.
const (
	// DefaultRPC is the default RPC endpoint URL for blockchain connectivity.
	DefaultRPC = "https://rpc-new.pila.vn"
	// DefaultChainID is the default chain ID for the blockchain network.
	DefaultChainID = int64(704)
	// DefaultDIDSMCAddress is the default address of the DID Registry smart contract.
	DefaultDIDSMCAddress = "0x75e7b09a24bce5a921babe27b62ec7bfe2230d6a"
	// DefaultMethod is the default DID method identifier (e.g., "did:nda").
	DefaultMethod = "did:nda"
)

// DIDConfig holds configuration for DID operations.
//
// Configuration can be set via functional options when creating a DIDGenerator,
// or passed directly to individual operations.
//
// Important notes:
//   - Epoch defaults to 0 if not set
//   - CapID is automatically generated if empty
//   - IssuerSigner is required for creating issuer signatures
//   - DIDSigner is required for signing transactions
//   - SyncEpoch and SyncNonce require a valid, accessible RPC URL
type DIDConfig struct {
	// RPC is the blockchain RPC endpoint URL for network connectivity.
	RPC string
	// ChainID is the blockchain network chain ID.
	ChainID int64
	// DIDSMCAddr is the address of the DID Registry smart contract.
	DIDSMCAddr string
	// Method is the DID method identifier (e.g., "did:nda").
	Method string
	// IssuerSigner is the signer provider for the Issuer (creates issuer signatures).
	// Required for generating issuer signatures.
	IssuerSigner signer.SignerProvider
	// DIDSigner is the signer provider for the DID (signs transactions).
	// Required for creating and signing transactions.
	DIDSigner signer.SignerProvider
	// Nonce is the transaction nonce for the DID signer account.
	// Defaults to 0 if not set. Can be synced from blockchain if SyncNonce is true.
	Nonce uint64
	// Epoch is the capability epoch for issuer signature validation.
	// Defaults to 0 if not set. Can be synced from blockchain if SyncEpoch is true.
	Epoch uint64
	// CapID is the capability ID for this specific DID issuance.
	// Automatically generated if empty.
	CapID string
	// SyncEpoch enables automatic synchronization of epoch from the blockchain.
	// Requires a valid, accessible RPC URL. If RPC is invalid, set to false and use manual epoch.
	SyncEpoch bool
	// SyncNonce enables automatic synchronization of nonce from the blockchain.
	// Requires a valid, accessible RPC URL. If RPC is invalid, set to false and use manual nonce.
	SyncNonce bool
}

// DIDOption is a functional option type for configuring DIDGenerator.
type DIDOption func(*DIDConfig)

// WithRPC sets the RPC endpoint URL for blockchain connectivity.
func WithRPC(rpc string) DIDOption {
	return func(c *DIDConfig) { c.RPC = rpc }
}

// WithDIDChainID sets the blockchain chain ID.
func WithDIDChainID(chainID int64) DIDOption {
	return func(c *DIDConfig) { c.ChainID = chainID }
}

// WithDIDAddressSMC sets the DID Registry smart contract address.
func WithDIDAddressSMC(addr string) DIDOption {
	return func(c *DIDConfig) { c.DIDSMCAddr = addr }
}

// WithMethod sets the DID method identifier (e.g., "did:nda").
func WithMethod(method string) DIDOption {
	return func(c *DIDConfig) { c.Method = method }
}

// WithEpoch sets the capability epoch manually.
//
// If not set, defaults to 0. Use WithSyncEpoch(true) to automatically
// sync from blockchain (requires valid RPC URL).
func WithEpoch(epoch uint64) DIDOption {
	return func(c *DIDConfig) { c.Epoch = epoch }
}

// WithIssuerSignerProvider sets the signer provider for the Issuer.
//
// The IssuerSigner is used to create issuer signatures that authorize DID issuance.
// This is required for generating issuer signatures.
func WithIssuerSignerProvider(p signer.SignerProvider) DIDOption {
	return func(c *DIDConfig) { c.IssuerSigner = p }
}

// WithDIDSignerProvider sets the signer provider for the DID.
//
// The DIDSigner is used to sign transactions for creating DIDs on-chain.
// This is required for creating and signing transactions.
func WithDIDSignerProvider(p signer.SignerProvider) DIDOption {
	return func(c *DIDConfig) { c.DIDSigner = p }
}

// WithSyncEpoch enables automatic synchronization of epoch from the blockchain.
//
// Requires a valid, accessible RPC URL. If RPC is invalid or unavailable,
// set to false and use WithEpoch() to set the epoch manually (default is 0).
func WithSyncEpoch(sync bool) DIDOption {
	return func(c *DIDConfig) { c.SyncEpoch = sync }
}

// WithSyncNonce enables automatic synchronization of nonce from the blockchain.
//
// Requires a valid, accessible RPC URL. If RPC is invalid or unavailable,
// set to false and the nonce will default to 0.
func WithSyncNonce(sync bool) DIDOption {
	return func(c *DIDConfig) { c.SyncNonce = sync }
}

// WithCapID sets the capability ID for this DID issuance.
//
// If not set, a random CapID is automatically generated.
func WithCapID(capID string) DIDOption {
	return func(c *DIDConfig) { c.CapID = capID }
}

// WithDIDConfig sets the complete DID configuration from a DIDConfig struct.
func WithDIDConfig(config *DIDConfig) DIDOption {
	return func(c *DIDConfig) {
		c.RPC = config.RPC
		c.ChainID = config.ChainID
		c.DIDSMCAddr = strings.ToLower(config.DIDSMCAddr)
		c.Method = config.Method
		c.IssuerSigner = config.IssuerSigner
		c.DIDSigner = config.DIDSigner
		c.CapID = config.CapID
		c.Epoch = config.Epoch
		c.Nonce = config.Nonce
		c.SyncEpoch = config.SyncEpoch
		c.SyncNonce = config.SyncNonce
	}
}
