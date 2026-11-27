package issuer

import (
	"strings"
	"testing"
)

// Both capability payloads hold their id to validateCapID. The packer refuses
// non-hex later anyway, so only this test sees the check itself go.
func TestCapabilityPayloadsRefuseACapIDThatIsNotHex(t *testing.T) {
	addr := "0x00000000000000000000000000000000000000a1"
	notHex := "0x" + strings.Repeat("g", 64)

	update := (&UpdateCapabilityPayload{ContractAddress: addr, IssuerAddress: addr, DidAddress: addr, CapID: notHex}).Validate()
	create := (&IssueDIDPayload{ContractAddress: addr, IssuerAddress: addr, DidAddress: addr, CapID: notHex}).Validate()

	for name, err := range map[string]error{"update": update, "create": create} {
		if err == nil || !strings.Contains(err.Error(), "not hex") {
			t.Errorf("%s: %v", name, err)
		}
	}
}
