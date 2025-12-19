package config

// Default values
const (
	DefaultRPC        = "https://rpc-testnet.pila.vn"
	DefaultChainID    = 6789
	DefaultDIDAddress = "0x0000000000000000000000000000000000018888"
	DefaultMethod     = "did:nda"
)

// Config holds the configuration for DID operations
type Config struct {
	ChainID    int64
	DIDAddress string // contract address
	Method     string
}

// New creates a new Config instance with the provided values.
// If a value is empty/zero, it will use the default value.
// Pass an empty Config{} to use all defaults.
func New(cfg Config) *Config {
	result := &Config{
		ChainID:    DefaultChainID,
		DIDAddress: DefaultDIDAddress,
		Method:     DefaultMethod,
	}

	if cfg.ChainID != 0 {
		result.ChainID = cfg.ChainID
	}
	if cfg.DIDAddress != "" {
		result.DIDAddress = cfg.DIDAddress
	}
	if cfg.Method != "" {
		result.Method = cfg.Method
	}

	return result
}
