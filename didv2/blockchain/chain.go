package blockchain

// AttributeValiditySeconds defines the validity period for DID attributes (1 day).
const AttributeValiditySeconds = 86400

// MaxAttributeNameLength defines the maximum length for attribute names (32 bytes).
const MaxAttributeNameLength = 32

// SubmitTxResult represents a pre-built Ethereum transaction for DID operations.
// It is intentionally decoupled from any broadcasting logic so that callers can
// decide how and when to submit the transaction on-chain.
type SubmitTxResult struct {
	TxHex     string // Hex-encoded RLP transaction
	TxHash    string // Transaction hash
	IsSuccess bool   // Optional flag that builders may use to indicate local success
}
