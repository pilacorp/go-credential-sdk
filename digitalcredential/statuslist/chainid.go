package statuslist

import (
	"fmt"
	"strconv"
	"strings"
)

const chainIDPrefix = "dc-b"

// ChainListID returns the id under which the issuer anchors List.Bytes() with
// updateRevokeStatusList: "dc-b<bits>-<listID>", e.g. dc-b1-7, dc-b2-15.
// listID is the global id of the list. VC lists use digits only, so the two
// never collide; the bit width is in the id so that anyone reading the chain
// without the token knows how to read the bytes.
func ChainListID(bits int, listID uint64) (string, error) {
	if !validBits(bits) {
		return "", fmt.Errorf("%w: bits %d, want 1, 2, 4 or 8", ErrInvalidArgument, bits)
	}
	return chainIDPrefix + strconv.Itoa(bits) + "-" + strconv.FormatUint(listID, 10), nil
}

// ParseChainListID reverses ChainListID. It accepts only the form ChainListID
// writes, so one list has one id: bits one of 1, 2, 4, 8; listID decimal
// digits without sign or leading zero, within uint64.
func ParseChainListID(id string) (bits int, listID uint64, err error) {
	rest, ok := strings.CutPrefix(id, chainIDPrefix)
	if !ok || len(rest) < 3 || rest[1] != '-' {
		return 0, 0, fmt.Errorf("%w: chain list id %q is not dc-b<bits>-<listID>", ErrMalformed, id)
	}
	bits = int(rest[0] - '0')
	if !validBits(bits) {
		return 0, 0, fmt.Errorf("%w: chain list id %q: bits must be 1, 2, 4 or 8", ErrMalformed, id)
	}
	// ParseUint in base 10 accepts ASCII digits only: no sign, no underscore.
	digits := rest[2:]
	if len(digits) > 1 && digits[0] == '0' {
		return 0, 0, fmt.Errorf("%w: chain list id %q: listID has a leading zero", ErrMalformed, id)
	}
	listID, err = strconv.ParseUint(digits, 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("%w: chain list id %q: %v", ErrMalformed, id, err)
	}
	return bits, listID, nil
}
