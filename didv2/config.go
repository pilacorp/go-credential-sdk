package didv2

import (
	"strings"

	"github.com/pilacorp/go-credential-sdk/didv2/signer"
)

// Default configuration constants
// Let change these values if you want to use a different network.
const (
	DefaultRPC           = "https://rpc-new.pila.vn"
	DefaultChainID       = int64(704)
	DefaultDIDSMCAddress = "0x75e7b09a24bce5a921babe27b62ec7bfe2230d6a"
	DefaultMethod        = "did:nda"
)

// DIDConfig holds configuration for a specific operation.
//
// Epoch default is 0.
// CapID if empty will be generated randomly.
// IssuerSigner is the signer who will issue the DID.
// DIDSigner is the signer who will sign the DID create transaction.
type DIDConfig struct {
	RPC          string
	ChainID      int64
	DIDSMCAddr   string
	Method       string
	IssuerSigner signer.SignerProvider
	DIDSigner    signer.SignerProvider
	Nonce        uint64
	Epoch        uint64
	CapID        string
	SyncEpoch    bool
	SyncNonce    bool
}

type DIDOption func(*DIDConfig)

// -- Option Functions --

func WithRPC(rpc string) DIDOption {
	return func(c *DIDConfig) { c.RPC = rpc }
}

func WithDIDChainID(chainID int64) DIDOption {
	return func(c *DIDConfig) { c.ChainID = chainID }
}

func WithDIDAddressSMC(addr string) DIDOption {
	return func(c *DIDConfig) { c.DIDSMCAddr = addr }
}

func WithMethod(method string) DIDOption {
	return func(c *DIDConfig) { c.Method = method }
}

func WithEpoch(epoch uint64) DIDOption {
	return func(c *DIDConfig) { c.Epoch = epoch }
}

func WithIssuerSignerProvider(p signer.SignerProvider) DIDOption {
	return func(c *DIDConfig) { c.IssuerSigner = p }
}

func WithDIDSignerProvider(p signer.SignerProvider) DIDOption {
	return func(c *DIDConfig) { c.DIDSigner = p }
}

func WithSyncEpoch(sync bool) DIDOption {
	return func(c *DIDConfig) { c.SyncEpoch = sync }
}

func WithSyncNonce(sync bool) DIDOption {
	return func(c *DIDConfig) { c.SyncNonce = sync }
}

func WithCapID(capID string) DIDOption {
	return func(c *DIDConfig) { c.CapID = capID }
}

// WithDIDConfig sets the DID configuration.
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
