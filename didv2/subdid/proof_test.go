package subdid

import (
	"encoding/json"
	"reflect"
	"testing"
)

const proofResponseJSON = `{
  "did": "did:nda:0x5995…", "root_did": "did:nda:0xa0dc…", "tree_index": "0x6f1c…b47d",
  "chains": [
    { "chain": "did", "tx_hash": "0x3c71…", "root": "0x9c2d…", "path": ["0x8f2c…"], "status": "activated" },
    { "chain": "trace", "tx_hash": "0x51e0…", "root": "0x77ab…", "path": ["0x8f2c…"], "status": "deactivated" }
  ]
}`

func TestProofResponse_DecodesTheExampleAnswer(t *testing.T) {
	want := ProofResponse{
		DID: "did:nda:0x5995…", RootDID: "did:nda:0xa0dc…", TreeIndex: "0x6f1c…b47d",
		Chains: []ChainProof{
			{Chain: "did", TxHash: "0x3c71…", Root: "0x9c2d…", Path: []string{"0x8f2c…"}, Status: "activated"},
			{Chain: "trace", TxHash: "0x51e0…", Root: "0x77ab…", Path: []string{"0x8f2c…"}, Status: "deactivated"},
		},
	}

	var got ProofResponse
	if err := json.Unmarshal([]byte(proofResponseJSON), &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("decoded %+v, want %+v", got, want)
	}
}
