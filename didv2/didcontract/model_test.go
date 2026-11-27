package didcontract

import (
	"math/big"
	"strings"
	"testing"

	"github.com/pilacorp/go-credential-sdk/didv2/issuer"
)

// The docHash and capID checks refuse non-hex themselves. hexToBytes32 refuses
// it a step later anyway, so only this test sees the request-level check go.
func TestRequestsRefuseAHashThatIsNotHex(t *testing.T) {
	notHex := "0x" + strings.Repeat("g", 64)
	hash := "0x" + strings.Repeat("a", 64)
	addr := "0x00000000000000000000000000000000000000a1"
	sig := &issuer.Signature{V: big.NewInt(27), R: big.NewInt(1), S: big.NewInt(1)}

	for name, err := range map[string]error{
		"by issuer, docHash": (&SetAttributeByIssuerRequest{DIDAddress: addr, Name: "key/1", Value: []byte("v"), DocHash: notHex}).Validate(),
		"by DID, docHash": (&SetAttributeRequest{IssuerAddress: addr, Name: "key/1", Value: []byte("v"),
			DocHash: notHex, CapID: hash, CapabilitySig: sig}).Validate(),
		"by DID, capID": (&SetAttributeRequest{IssuerAddress: addr, Name: "key/1", Value: []byte("v"),
			DocHash: hash, CapID: notHex, CapabilitySig: sig}).Validate(),
	} {
		if err == nil || !strings.Contains(err.Error(), "not hex") {
			t.Errorf("%s: %v", name, err)
		}
	}
}
