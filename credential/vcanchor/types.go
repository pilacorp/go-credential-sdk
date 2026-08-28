package vcanchor

const HashSchemeKeccak256SortedPairsNoLeafHashV1 = "keccak256-sorted-pairs-no-leaf-hash-v1"

// Values of SubmitRootResponse.Status, the anchoring state the service reports for a
// submitted root. Anchoring is asynchronous: a root is StatusPending from the first
// submit until it lands on chain, and only StatusAnchored carries a tx hash. Treat any
// other value as not anchored. StoredBatch.Status is a different field with a
// different domain; see its doc.
const (
	StatusPending  = "pending"
	StatusAnchored = "anchored"
)

// MaxLeavesPerBatch caps how many VC hashes a single batch (one Merkle root)
// may contain. It bounds the memory used while building the tree and generating
// proofs. Split larger sets across multiple batches/roots.
const MaxLeavesPerBatch = 10000

type BatchInput struct {
	IssuerDID      string
	ExternalTreeID string
	VCHashes       []string
}

type Batch struct {
	IssuerDID      string `json:"issuer_did"`
	ExternalTreeID string `json:"external_tree_id"`
	Root           string `json:"root"`
	LeafCount      int    `json:"leaf_count"`
	HashScheme     string `json:"hash_scheme"`
	LeavesDigest   string `json:"leaves_digest"`

	leavesByHash map[[32]byte]int
	leaves       [][]byte
}

// SubmitRootRequest carries no batch identifier: the service identifies a tree by what
// it commits to — issuer, root and leaf count — so submitting the same tree twice is a
// poll rather than a second anchor. ExternalTreeID stays an SDK-local key for the
// Store; it never goes on the wire.
type SubmitRootRequest struct {
	IssuerDID    string `json:"issuer_did"`
	Root         string `json:"root"`
	LeafCount    int    `json:"leaf_count"`
	HashScheme   string `json:"hash_scheme"`
	LeavesDigest string `json:"leaves_digest"`
}

type SubmitRootResponse struct {
	ID               int    `json:"id"`
	IssuerDID        string `json:"issuer_did"`
	OnchainTreeIndex int    `json:"onchain_tree_index"`
	Root             string `json:"root"`
	LeafCount        int    `json:"leaf_count"`
	TxHash           string `json:"tx_hash"`
	Status           string `json:"status"`
	// AnchoredAt is RFC 3339, and empty while the root is pending.
	AnchoredAt string `json:"anchored_at"`
}

type Receipt struct {
	IssuerDID      string   `json:"issuer_did"`
	ExternalTreeID string   `json:"external_tree_id"`
	VCHash         string   `json:"vc_hash"`
	LeafIndex      int      `json:"leaf_index"`
	LeafCount      int      `json:"leaf_count"`
	Root           string   `json:"root"`
	Proof          []string `json:"proof"`
	TxHash         string   `json:"tx_hash,omitempty"`
	HashScheme     string   `json:"hash_scheme"`
}

type StoredBatch struct {
	IssuerDID       string   `json:"issuer_did"`
	ExternalTreeID  string   `json:"external_tree_id"`
	Root            string   `json:"root"`
	LeafCount       int      `json:"leaf_count"`
	HashScheme      string   `json:"hash_scheme"`
	LeavesDigest    string   `json:"leaves_digest"`
	OrderedVCHashes []string `json:"ordered_vc_hashes"`
	TxHash          string   `json:"tx_hash,omitempty"`
	// Status is the batch's local lifecycle state, not the service's: "created" when
	// the SDK first hands the batch to the Store, then whatever the Store writes in
	// MarkAnchored. It is not drawn from the StatusPending/StatusAnchored set above,
	// which describes SubmitRootResponse.Status.
	Status           string `json:"status"`
	AnchoredAtUnix   int64  `json:"anchored_at_unix,omitempty"`
	CreatedAtUnix    int64  `json:"created_at_unix"`
	LastModifiedUnix int64  `json:"last_modified_unix"`
}

type Manifest struct {
	IssuerDID      string `json:"issuer_did"`
	ExternalTreeID string `json:"external_tree_id"`
	Root           string `json:"root"`
	LeafCount      int    `json:"leaf_count"`
	HashScheme     string `json:"hash_scheme"`
	LeavesDigest   string `json:"leaves_digest"`
}
