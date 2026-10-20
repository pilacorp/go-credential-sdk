package subdid

// ProofResponse is the JSON answer of GET /api/v3/sub-did/{did}/proof.
type ProofResponse struct {
	DID       string       `json:"did"`
	RootDID   string       `json:"root_did"`
	TreeIndex string       `json:"tree_index"`
	Chains    []ChainProof `json:"chains"`
}

// ChainProof is the proof of the Sub-DID's leaf in the last root one chain anchored.
type ChainProof struct {
	Chain  string   `json:"chain"`
	TxHash string   `json:"tx_hash"`
	Root   string   `json:"root"`
	Path   []string `json:"path"`
	Status string   `json:"status"`
}
