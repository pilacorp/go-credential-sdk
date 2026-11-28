package didcontract

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// TestReadsReportWhyRPCIsUnavailable checks that a contract built without a
// working RPC still constructs, and that read operations then return the reason
// instead of a generic message.
func TestReadsReportWhyRPCIsUnavailable(t *testing.T) {
	for _, tt := range []struct {
		name, rpcURL, wantInErr string
	}{
		{"no RPC URL", "", "no RPC URL is configured"},
		{"unsupported scheme", "foo://rpc.example", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewContract(&Config{
				RPCURL:          tt.rpcURL,
				ContractAddress: "0x75e7b09a24bce5a921babe27b62ec7bfe2230d6a",
				ChainID:         1,
			})
			if err != nil {
				t.Fatalf("NewContract: %v", err)
			}
			defer c.Close()
			// The dial error is wrapped, so its cause stays reachable.
			_, nonceErr := c.GetNonce(context.Background(), common.Address{})
			_, epochErr := c.GetCapabilityEpoch(context.Background(), "0x5b6a5525e2c2d2428554b04d24b3bb5c1f3f5ae3")
			for name, err := range map[string]error{"GetNonce": nonceErr, "GetCapabilityEpoch": epochErr} {
				if err == nil || errors.Unwrap(err) == nil || !strings.Contains(err.Error(), tt.wantInErr) {
					t.Errorf("%s error = %v, want a wrapped cause containing %q", name, err, tt.wantInErr)
				}
			}
		})
	}
}
