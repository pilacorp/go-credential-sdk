package vcanchor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestServiceClientSubmitRootUsesIssuerHeaderAndRequestBody(t *testing.T) {
	t.Parallel()

	var gotIssuerHeader string
	var gotAuthorization string
	var gotBody map[string]any

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/credentials/external/merkle-roots" {
			t.Fatalf("got path %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Fatalf("got method %s", r.Method)
		}

		gotIssuerHeader = r.Header.Get("x-issuer-did")
		gotAuthorization = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatalf("Decode body returned error: %v", err)
		}
		if _, ok := gotBody["issuer_did"]; ok {
			t.Fatal("submit root body must not include issuer_did; service reads it from x-issuer-did")
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"id": 7,
			"issuer_did": "did:pila:testnet:0xissuer",
			"external_tree_id": "tree-1",
			"onchain_tree_index": 1000000001,
			"root": "0xroot",
			"leaf_count": 2,
			"hash_scheme": "keccak256-sorted-pairs-no-leaf-hash-v1",
			"leaves_digest": "0xdigest",
			"tx_hash": "0xtx",
			"status": "anchored"
		}`))
	}))
	t.Cleanup(server.Close)

	client := NewServiceClient(server.URL, "did:pila:testnet:0xissuer", WithAuthorization("Bearer token"))
	resp, err := client.SubmitRoot(context.Background(), SubmitRootRequest{
		IssuerDID:      "did:pila:testnet:0xissuer",
		ExternalTreeID: "tree-1",
		Root:           "0xroot",
		LeafCount:      2,
		HashScheme:     HashSchemeKeccak256SortedPairsNoLeafHashV1,
		LeavesDigest:   "0xdigest",
	})
	if err != nil {
		t.Fatalf("SubmitRoot returned error: %v", err)
	}

	if gotIssuerHeader != "did:pila:testnet:0xissuer" {
		t.Fatalf("got x-issuer-did %q", gotIssuerHeader)
	}
	if gotAuthorization != "Bearer token" {
		t.Fatalf("got Authorization %q", gotAuthorization)
	}
	if gotBody["external_tree_id"] != "tree-1" {
		t.Fatalf("got external_tree_id %v", gotBody["external_tree_id"])
	}
	if resp.TxHash != "0xtx" {
		t.Fatalf("got tx hash %q", resp.TxHash)
	}
	if resp.OnchainTreeIndex != 1000000001 {
		t.Fatalf("got onchain tree index %d", resp.OnchainTreeIndex)
	}
}

func TestServiceClientSubmitRootRejectsMismatchedIssuerDID(t *testing.T) {
	t.Parallel()

	requested := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested = true
	}))
	t.Cleanup(server.Close)

	client := NewServiceClient(server.URL, "did:pila:testnet:0xclient")
	_, err := client.SubmitRoot(context.Background(), SubmitRootRequest{
		IssuerDID:      "did:pila:testnet:0xrequest",
		ExternalTreeID: "tree-1",
		Root:           "0xroot",
		LeafCount:      2,
		HashScheme:     HashSchemeKeccak256SortedPairsNoLeafHashV1,
		LeavesDigest:   "0xdigest",
	})
	if err == nil {
		t.Fatal("expected issuer mismatch error")
	}
	if !strings.Contains(err.Error(), "issuer_did does not match service client issuer") {
		t.Fatalf("got error %q", err)
	}
	if requested {
		t.Fatal("SubmitRoot must not send request when issuer DID mismatches")
	}
}

func TestServiceClientVerifyReceiptSendsFullReceiptPayload(t *testing.T) {
	t.Parallel()

	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/credentials/external/verify-receipt" {
			t.Fatalf("got path %s", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatalf("Decode body returned error: %v", err)
		}
		if gotBody["root"] != "0xroot" {
			t.Fatalf("got root %v", gotBody["root"])
		}
		proof, ok := gotBody["proof"].([]any)
		if !ok || len(proof) != 1 || proof[0] != "0xsibling" {
			t.Fatalf("got proof %#v", gotBody["proof"])
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"verified":true,"source":"proof","proof_required":false}`))
	}))
	t.Cleanup(server.Close)

	client := NewServiceClient(server.URL, "")
	resp, err := client.VerifyReceipt(context.Background(), Receipt{
		IssuerDID:      "did:pila:testnet:0xissuer",
		ExternalTreeID: "tree-1",
		VCHash:         "0xhash",
		LeafIndex:      3,
		Root:           "0xroot",
		Proof:          []string{"0xsibling"},
		TxHash:         "0xtx",
		HashScheme:     HashSchemeKeccak256SortedPairsNoLeafHashV1,
	})
	if err != nil {
		t.Fatalf("VerifyReceipt returned error: %v", err)
	}
	if !resp.Verified {
		t.Fatal("expected verified=true")
	}
	if resp.Source != "proof" {
		t.Fatalf("got source %q", resp.Source)
	}
}

func TestServiceClientVerifyReceiptAcceptsCacheResponse(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/credentials/external/verify-receipt" {
			t.Fatalf("got path %s", r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"verified":true,"source":"cache","proof_required":false}`))
	}))
	t.Cleanup(server.Close)

	client := NewServiceClient(server.URL, "")
	resp, err := client.VerifyReceipt(context.Background(), Receipt{
		IssuerDID:      "did:pila:testnet:0xissuer",
		ExternalTreeID: "tree-1",
		VCHash:         "0xhash",
		LeafIndex:      3,
		Root:           "0xroot",
		Proof:          []string{"0xsibling"},
		TxHash:         "0xtx",
		HashScheme:     HashSchemeKeccak256SortedPairsNoLeafHashV1,
	})
	if err != nil {
		t.Fatalf("VerifyReceipt returned error: %v", err)
	}
	if !resp.Verified {
		t.Fatal("expected verified=true")
	}
	if resp.Source != "cache" {
		t.Fatalf("got source %q", resp.Source)
	}
}
