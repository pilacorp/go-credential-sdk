package subdid

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"regexp"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/pilacorp/go-credential-sdk/didv2/did"
	"github.com/pilacorp/go-credential-sdk/didv2/didcontract"
)

const (
	statusActivated   = "activated"
	statusDeactivated = "deactivated"
)

type Reason string

const (
	ReasonResponseMismatch Reason = "response_mismatch"
	ReasonIDMismatch       Reason = "id_mismatch"
	ReasonConsentInvalid   Reason = "consent_invalid"
	ReasonNoAnchor         Reason = "no_anchor"
	ReasonRootMismatch     Reason = "root_mismatch"
	ReasonWriterRevoked    Reason = "writer_revoked"
	ReasonProofMismatch    Reason = "proof_mismatch"
)

var hash32Pattern = regexp.MustCompile(`^0x[0-9a-f]{64}$`)

var (
	// ErrNotAnchored comes from the proof alone; no chain is read.
	ErrNotAnchored      = errors.New("subdid: the chain has not anchored this Sub-DID yet")
	ErrDocumentRequired = errors.New("subdid: an activated Sub-DID needs its document")
	ErrChainUnavailable = errors.New("subdid: the chain could not be read")
	ErrChainMismatch    = errors.New("subdid: node reports another chain id")
)

// ChainClient is satisfied by *ethclient.Client.
type ChainClient interface {
	ChainID(ctx context.Context) (*big.Int, error)
	TransactionReceipt(ctx context.Context, h common.Hash) (*types.Receipt, error)
	CallContract(ctx context.Context, msg ethereum.CallMsg, block *big.Int) ([]byte, error)
}

type Chain struct {
	Code        string // catalog chain code, e.g. "did", "trace"
	EVMChainID  int64
	DIDRegistry common.Address // must be DIDRegistry 2.1
	Client      ChainClient
}

// Verifier is safe for concurrent use.
type Verifier struct {
	chains map[string]Chain
}

// NewVerifier makes no network call.
func NewVerifier(chains ...Chain) (*Verifier, error) {
	if len(chains) == 0 {
		return nil, errors.New("subdid: a verifier needs at least one chain")
	}

	byCode := make(map[string]Chain, len(chains))
	for _, c := range chains {
		switch {
		case c.Code == "":
			return nil, errors.New("subdid: chain code is empty")
		case c.EVMChainID <= 0:
			return nil, fmt.Errorf("subdid: chain %s: EVM chain id must be positive", c.Code)
		case c.DIDRegistry == (common.Address{}):
			return nil, fmt.Errorf("subdid: chain %s: DID registry address is zero", c.Code)
		case c.Client == nil:
			return nil, fmt.Errorf("subdid: chain %s: client is nil", c.Code)
		}
		if _, ok := byCode[c.Code]; ok {
			return nil, fmt.Errorf("subdid: chain %s is configured twice", c.Code)
		}
		byCode[c.Code] = c
	}

	return &Verifier{chains: byCode}, nil
}

type VerifyRequest struct {
	SubDID   string
	Document *did.DIDDocument // optional: without it only a revoked leaf can be proven
	Proof    *ProofResponse   // from GetSubDIDProof
	Chain    string
}

type Status int

const (
	StatusInvalid Status = iota
	StatusActive
	StatusRevoked
)

type Result struct {
	Status Status
	Reason Reason // empty for StatusActive and StatusRevoked
	Chain  string
	TxHash common.Hash
}

// VerifySubDID returns an error, never StatusInvalid, when the chain cannot be read.
// A proof fetched before a revoke still verifies; one from a since-removed writer reads writer_revoked.
func (v *Verifier) VerifySubDID(ctx context.Context, req VerifyRequest) (Result, error) {
	if req.Proof == nil {
		return Result{}, errors.New("subdid: proof is nil")
	}
	if err := checkDID(req.SubDID); err != nil {
		return Result{}, fmt.Errorf("subdid: Sub-DID: %w", err)
	}
	c, ok := v.chains[req.Chain]
	if !ok {
		return Result{}, fmt.Errorf("subdid: chain %q is not configured", req.Chain)
	}

	invalid := func(reason Reason) (Result, error) {
		return Result{Status: StatusInvalid, Reason: reason, Chain: c.Code}, nil
	}

	proof := req.Proof
	if !consistentProof(proof, req.SubDID) {
		return invalid(ReasonResponseMismatch)
	}

	entry, err := chainEntry(proof, c.Code)
	if err != nil {
		return Result{}, err
	}
	anchor, ok := parseChainProof(entry)
	if !ok {
		return invalid(ReasonResponseMismatch)
	}

	var leaf [32]byte
	verdict := StatusActive
	switch entry.Status {
	case statusActivated:
		if req.Document == nil {
			return Result{}, ErrDocumentRequired
		}
		if req.Document.Id != req.SubDID || ValidateSubDID(req.Document, proof.RootDID) != nil {
			return invalid(ReasonIDMismatch)
		}
		if VerifyRootConsent(req.Document, proof.RootDID) != nil {
			return invalid(ReasonConsentInvalid)
		}
		if leaf, err = DocHash(req.Document); err != nil {
			return Result{}, err
		}
	case statusDeactivated:
		leaf = RevokedLeaf(common.HexToAddress(didAddress(req.SubDID)))
		verdict = StatusRevoked
	default:
		return invalid(ReasonResponseMismatch)
	}

	reason, err := checkOnChain(ctx, c, proof, anchor, leaf)
	if err != nil {
		return Result{}, err
	}
	if reason != "" {
		return invalid(reason)
	}

	return Result{Status: verdict, Chain: c.Code, TxHash: anchor.txHash}, nil
}

func consistentProof(proof *ProofResponse, subDID string) bool {
	if proof.DID != subDID || checkDID(proof.RootDID) != nil ||
		didPrefix(proof.RootDID) != didPrefix(subDID) || proof.RootDID == subDID {
		return false
	}

	return hash32Pattern.MatchString(proof.TreeIndex) || (proof.TreeIndex == "" && len(proof.Chains) == 0)
}

func chainEntry(proof *ProofResponse, code string) (ChainProof, error) {
	for _, entry := range proof.Chains {
		if entry.Chain == code {
			return entry, nil
		}
	}

	return ChainProof{}, fmt.Errorf("%w: chain %s", ErrNotAnchored, code)
}

type parsedChainProof struct {
	txHash common.Hash
	root   [32]byte
	path   [][32]byte
}

func parseChainProof(entry ChainProof) (parsedChainProof, bool) {
	txHash, ok := parseHash32(entry.TxHash)
	if !ok {
		return parsedChainProof{}, false
	}
	root, ok := parseHash32(entry.Root)
	if !ok {
		return parsedChainProof{}, false
	}

	path := make([][32]byte, len(entry.Path))
	for i, s := range entry.Path {
		if path[i], ok = parseHash32(s); !ok {
			return parsedChainProof{}, false
		}
	}

	return parsedChainProof{txHash: txHash, root: root, path: path}, true
}

func parseHash32(s string) ([32]byte, bool) {
	if !hash32Pattern.MatchString(s) {
		return [32]byte{}, false
	}

	b, err := hex.DecodeString(s[2:])
	if err != nil {
		return [32]byte{}, false
	}

	return [32]byte(b), true
}

func checkOnChain(ctx context.Context, c Chain, proof *ProofResponse, anchor parsedChainProof, leaf [32]byte) (Reason, error) {
	if !VerifyProof(leaf, anchor.path, anchor.root) {
		return ReasonProofMismatch, nil
	}

	chainID, err := c.Client.ChainID(ctx)
	if err != nil {
		return "", fmt.Errorf("%w: chain %s: %w", ErrChainUnavailable, c.Code, err)
	}
	if chainID == nil || chainID.Cmp(big.NewInt(c.EVMChainID)) != 0 {
		return "", fmt.Errorf("%w: %w: chain %s: node reports %v, want %d",
			ErrChainUnavailable, ErrChainMismatch, c.Code, chainID, c.EVMChainID)
	}

	receipt, err := c.Client.TransactionReceipt(ctx, anchor.txHash)
	if err != nil {
		return "", fmt.Errorf("%w: chain %s: receipt %s: %w", ErrChainUnavailable, c.Code, anchor.txHash.Hex(), err)
	}
	if receipt == nil {
		return "", fmt.Errorf("%w: chain %s: receipt %s is empty", ErrChainUnavailable, c.Code, anchor.txHash.Hex())
	}
	if receipt.Status != types.ReceiptStatusSuccessful {
		return ReasonNoAnchor, nil
	}

	written, ok := lastWriterAnchor(receipt, c.DIDRegistry, proof)
	if !ok {
		return ReasonNoAnchor, nil
	}
	if written.Root != anchor.root {
		return ReasonRootMismatch, nil
	}

	isWriter, err := didcontract.HasRole(ctx, c.Client, c.DIDRegistry, didcontract.SubtreeWriterRole, written.Writer)
	if err != nil {
		return "", fmt.Errorf("%w: chain %s: %w", ErrChainUnavailable, c.Code, err)
	}
	if !isWriter {
		return ReasonWriterRevoked, nil
	}

	return "", nil
}

func lastWriterAnchor(receipt *types.Receipt, registry common.Address, proof *ProofResponse) (didcontract.WriterAnchor, bool) {
	anchors, err := didcontract.DecodeWriterAnchors(receipt, registry)
	if err != nil {
		return didcontract.WriterAnchor{}, false
	}

	rootAddress := common.HexToAddress(didAddress(proof.RootDID))
	treeIndex, ok := new(big.Int).SetString(proof.TreeIndex[2:], 16)
	if !ok {
		return didcontract.WriterAnchor{}, false
	}

	for i := len(anchors) - 1; i >= 0; i-- {
		if anchors[i].DID == rootAddress && anchors[i].TreeIndex.Cmp(treeIndex) == 0 {
			return anchors[i], true
		}
	}

	return didcontract.WriterAnchor{}, false
}
