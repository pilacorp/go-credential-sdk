package didv2

import (
	"github.com/pilacorp/go-credential-sdk/didv2/signer"
)

// Default configuration constants
const (
	DefaultRPC           = "https://rpc-testnet-new.pila.vn"
	DefaultChainID       = int64(704)
	DefaultDIDSMCAddress = "0x75e7b09a24bCE5a921bABE27b62ec7bfE2230d6A"
	DefaultMethod        = "did:nda"
)

// DIDConfig holds configuration for a specific operation.
type DIDConfig struct {
	RPC            string
	ChainID        int64
	DIDSMCAddress  string
	Method         string
	SignerProvider signer.SignerProvider
	Nonce          uint64
	Epoch          uint64
	CapID          string
	SyncEpoch      bool
	SyncNonce      bool
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
	return func(c *DIDConfig) { c.DIDSMCAddress = addr }
}

func WithMethod(method string) DIDOption {
	return func(c *DIDConfig) { c.Method = method }
}

func WithEpoch(epoch uint64) DIDOption {
	return func(c *DIDConfig) { c.Epoch = epoch }
}

func WithSignerProvider(p signer.SignerProvider) DIDOption {
	return func(c *DIDConfig) { c.SignerProvider = p }
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

// WithDIDConfig allows copying settings from an existing configuration object.
func WithDIDConfig(config *DIDConfig) DIDOption {
	return func(c *DIDConfig) {
		// Copy base fields
		if config.RPC != "" {
			c.RPC = config.RPC
		}
		if config.ChainID != 0 {
			c.ChainID = config.ChainID
		}
		if config.DIDSMCAddress != "" {
			c.DIDSMCAddress = config.DIDSMCAddress
		}
		if config.Method != "" {
			c.Method = config.Method
		}

		// Copy optional/runtime fields if they are set/relevant
		if config.SignerProvider != nil {
			c.SignerProvider = config.SignerProvider
		}
		if config.CapID != "" {
			c.CapID = config.CapID
		}

		// Boolean flags and integers (0 is valid, so we copy directly)
		c.Epoch = config.Epoch
		c.Nonce = config.Nonce
		c.SyncEpoch = config.SyncEpoch
		c.SyncNonce = config.SyncNonce
	}
}
