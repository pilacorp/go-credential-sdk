package vcanchor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestServiceClientSubmitRootUsesIssuerHeaderAndRequestBody(t *testing.T) {
	t.Parallel()

	var gotIssuerHeader string
	var gotAuthorization string
	var gotBody map[string]any

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/credentials/merkle-roots" {
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
			"onchain_tree_index": 12,
			"root": "0xroot",
			"leaf_count": 2,
			"tx_hash": "0xtx",
			"status": "anchored",
			"anchored_at": "2026-08-28T03:04:05Z"
		}`))
	}))
	t.Cleanup(server.Close)

	client := NewServiceClient(server.URL, "did:pila:testnet:0xissuer", WithAuthorization("Bearer token"))
	resp, err := client.SubmitRoot(context.Background(), SubmitRootRequest{
		IssuerDID: "did:pila:testnet:0xissuer",
		Root:      "0xroot",
		LeafCount: 2,
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
	// The service identifies a tree by its content and folds nothing, so nothing but
	// that content may leak onto the wire — a field the service does not act on reads
	// like one it honours.
	for _, unexpected := range []string{"external_tree_id", "hash_scheme", "leaves_digest"} {
		if _, ok := gotBody[unexpected]; ok {
			t.Fatalf("request body carried %s: %v", unexpected, gotBody)
		}
	}
	if gotBody["root"] != "0xroot" || gotBody["leaf_count"] != float64(2) {
		t.Fatalf("got body %v", gotBody)
	}
	if resp.TxHash != "0xtx" {
		t.Fatalf("got tx hash %q", resp.TxHash)
	}
	if resp.OnchainTreeIndex != 12 {
		t.Fatalf("got onchain tree index %d", resp.OnchainTreeIndex)
	}
	if resp.AnchoredAt != "2026-08-28T03:04:05Z" {
		t.Fatalf("got anchored_at %q", resp.AnchoredAt)
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
		IssuerDID: "did:pila:testnet:0xrequest",
		Root:      "0xroot",
		LeafCount: 2,
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

// GetRoot must be a plain GET with the lookup in the query string: no body, nothing
// the service could read as a submission.
func TestServiceClientGetRootUsesGETWithQueryParams(t *testing.T) {
	t.Parallel()

	var (
		gotMethod        string
		gotQuery         url.Values
		gotIssuerHeader  string
		gotContentLength int64
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/credentials/merkle-roots" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}

		gotMethod = r.Method
		gotQuery = r.URL.Query()
		gotIssuerHeader = r.Header.Get("x-issuer-did")
		gotContentLength = r.ContentLength

		_, _ = w.Write([]byte(`{
			"id": 42,
			"issuer_did": "did:pila:testnet:0xissuer",
			"onchain_tree_index": 12,
			"root": "0xroot",
			"leaf_count": 2,
			"tx_hash": "0xtx",
			"status": "anchored",
			"anchored_at": "2026-08-28T03:04:05Z"
		}`))
	}))
	t.Cleanup(server.Close)

	client := NewServiceClient(server.URL, "did:pila:testnet:0xissuer", WithAuthorization("Bearer token"))

	resp, err := client.GetRoot(context.Background(), "did:pila:testnet:0xissuer", "0xroot", 2)
	if err != nil {
		t.Fatalf("GetRoot returned error: %v", err)
	}

	if gotMethod != http.MethodGet {
		t.Fatalf("method = %q, want GET", gotMethod)
	}
	if gotContentLength > 0 {
		t.Fatalf("GetRoot sent a %d byte body; a read must not carry one", gotContentLength)
	}
	if gotQuery.Get("root") != "0xroot" || gotQuery.Get("leaf_count") != "2" {
		t.Fatalf("query = %v", gotQuery)
	}
	if gotIssuerHeader != "did:pila:testnet:0xissuer" {
		t.Fatalf("x-issuer-did = %q", gotIssuerHeader)
	}
	if resp.Status != StatusAnchored || resp.TxHash != "0xtx" {
		t.Fatalf("resp = %+v", resp)
	}
}
