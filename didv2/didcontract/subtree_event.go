package didcontract

import (
	"context"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

const (
	writerAnchorEvent = "BatchSubtreesAnchoredByWriter"
	hasRoleMethod     = "hasRole"
)

// SubtreeWriterRole is keccak256("SUBTREE_WRITER_ROLE").
var SubtreeWriterRole = common.HexToHash("0x6fc0b0d6b98862e3c914d0800fe475986e8788ba7b923ff2cc748cdb21b43243")

type WriterAnchor struct {
	Writer    common.Address
	DID       common.Address
	TreeIndex *big.Int
	Root      [32]byte
}

// DecodeWriterAnchors does not check receipt.Status.
func DecodeWriterAnchors(receipt *types.Receipt, registry common.Address) ([]WriterAnchor, error) {
	if receipt == nil {
		return nil, errors.New("didcontract: receipt is nil")
	}
	if registry == (common.Address{}) {
		return nil, errors.New("didcontract: registry address is zero")
	}

	contractABI, err := loadABI()
	if err != nil {
		return nil, err
	}
	eventID := contractABI.Events[writerAnchorEvent].ID

	var anchors []WriterAnchor
	for _, log := range receipt.Logs {
		if log == nil || log.Address != registry || len(log.Topics) == 0 || log.Topics[0] != eventID {
			continue
		}

		decoded, err := decodeWriterLog(contractABI, log)
		if err != nil {
			return nil, fmt.Errorf("didcontract: log %d: %w", log.Index, err)
		}
		anchors = append(anchors, decoded...)
	}

	return anchors, nil
}

func decodeWriterLog(contractABI abi.ABI, log *types.Log) ([]WriterAnchor, error) {
	if len(log.Topics) != 2 {
		return nil, fmt.Errorf("%s has %d topics, want 2", writerAnchorEvent, len(log.Topics))
	}

	var fields struct {
		Dids        []common.Address
		TreeIndexes []*big.Int
		Roots       [][32]byte
	}
	if err := contractABI.UnpackIntoInterface(&fields, writerAnchorEvent, log.Data); err != nil {
		return nil, fmt.Errorf("unpack %s: %w", writerAnchorEvent, err)
	}
	if len(fields.Dids) != len(fields.TreeIndexes) || len(fields.Dids) != len(fields.Roots) {
		return nil, fmt.Errorf("%s arrays have lengths %d, %d and %d",
			writerAnchorEvent, len(fields.Dids), len(fields.TreeIndexes), len(fields.Roots))
	}

	writer := common.BytesToAddress(log.Topics[1].Bytes())
	anchors := make([]WriterAnchor, len(fields.Dids))
	for i := range fields.Dids {
		anchors[i] = WriterAnchor{
			Writer:    writer,
			DID:       fields.Dids[i],
			TreeIndex: fields.TreeIndexes[i],
			Root:      fields.Roots[i],
		}
	}

	return anchors, nil
}

func HasRole(ctx context.Context, caller ethereum.ContractCaller, registry common.Address, role common.Hash, account common.Address) (bool, error) {
	contractABI, err := loadABI()
	if err != nil {
		return false, err
	}

	data, err := contractABI.Pack(hasRoleMethod, role, account)
	if err != nil {
		return false, fmt.Errorf("didcontract: pack %s: %w", hasRoleMethod, err)
	}

	out, err := caller.CallContract(ctx, ethereum.CallMsg{To: &registry, Data: data}, nil)
	if err != nil {
		return false, fmt.Errorf("didcontract: call %s: %w", hasRoleMethod, err)
	}
	if len(out) != 32 {
		return false, fmt.Errorf("didcontract: %s returned %d bytes, want 32", hasRoleMethod, len(out))
	}

	values, err := contractABI.Unpack(hasRoleMethod, out)
	if err != nil {
		return false, fmt.Errorf("didcontract: unpack %s: %w", hasRoleMethod, err)
	}

	isMember, ok := values[0].(bool)
	if !ok {
		return false, fmt.Errorf("didcontract: %s returned %T, want bool", hasRoleMethod, values[0])
	}

	return isMember, nil
}
