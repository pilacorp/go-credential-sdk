package vcanchor

import (
	"encoding/hex"
	"fmt"
	"strings"
)

func normalizeHash32(value string) (string, []byte, error) {
	rawHex := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(value)), "0x")
	raw, err := hex.DecodeString(rawHex)
	if err != nil {
		return "", nil, fmt.Errorf("invalid 32-byte hash %q: %w", value, err)
	}
	if len(raw) != 32 {
		return "", nil, fmt.Errorf("invalid 32-byte hash %q: got %d bytes", value, len(raw))
	}

	return "0x" + hex.EncodeToString(raw), raw, nil
}

func hexHash(raw []byte) string {
	return "0x" + hex.EncodeToString(raw)
}
