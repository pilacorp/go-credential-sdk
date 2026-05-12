package jsonmap

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
)

type truncatingSigner struct {
	base signer.SignerProvider
}

func (s *truncatingSigner) Sign(hashPayload []byte) ([]byte, error) {
	sig, err := s.base.Sign(hashPayload)
	if err != nil {
		return nil, err
	}
	if len(sig) == 65 {
		return sig[:64], nil
	}
	return sig, nil
}

func newTestResolverServer(t *testing.T, did, vmID, publicKeyHex string) *httptest.Server {
	t.Helper()

	doc := map[string]interface{}{
		"@context": []string{"https://www.w3.org/ns/did/v1"},
		"id":       did,
		"verificationMethod": []map[string]interface{}{
			{
				"id":           vmID,
				"type":         "EcdsaSecp256k1VerificationKey2019",
				"controller":   did,
				"publicKeyHex": "0x" + publicKeyHex,
			},
		},
	}

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/") {
			http.NotFound(w, r)
			return
		}
		if strings.TrimPrefix(r.URL.Path, "/") != url.PathEscape(did) {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	}))
}

func TestJSONMap_AddECDSAProof_Accepts64ByteSignature(t *testing.T) {
	priv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	privHex := hex.EncodeToString(crypto.FromECDSA(priv))
	pubHex := hex.EncodeToString(crypto.FromECDSAPub(&priv.PublicKey))

	did := "did:example:issuer"
	vmID := "did:example:issuer#key-1"
	resolverServer := newTestResolverServer(t, did, vmID, pubHex)
	defer resolverServer.Close()

	m := JSONMap{
		"issuer": "did:example:issuer",
		"type":   "VerifiableCredential",
	}

	defaultSigner, err := signer.NewDefaultProvider(privHex)
	if err != nil {
		t.Fatalf("NewDefaultProvider: %v", err)
	}

	err = (&m).AddECDSAProof(&truncatingSigner{base: defaultSigner}, vmID, "assertionMethod", resolverServer.URL)
	if err != nil {
		t.Fatalf("AddECDSAProof error: %v", err)
	}

	proofObj, ok := m["proof"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected proof to be a map, got %T", m["proof"])
	}
	pv, _ := proofObj["proofValue"].(string)
	if len(pv) != hex.EncodedLen(64) {
		t.Fatalf("expected proofValue hex length %d, got %d", hex.EncodedLen(64), len(pv))
	}
}

func TestJSONMap_AddECDSAProof_Accepts65ByteSignature(t *testing.T) {
	priv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	privHex := hex.EncodeToString(crypto.FromECDSA(priv))
	pubHex := hex.EncodeToString(crypto.FromECDSAPub(&priv.PublicKey))

	did := "did:example:issuer"
	vmID := "did:example:issuer#key-1"
	resolverServer := newTestResolverServer(t, did, vmID, pubHex)
	defer resolverServer.Close()

	m := JSONMap{
		"issuer": "did:example:issuer",
		"type":   "VerifiableCredential",
	}

	defaultSigner, err := signer.NewDefaultProvider(privHex)
	if err != nil {
		t.Fatalf("NewDefaultProvider: %v", err)
	}

	err = (&m).AddECDSAProof(defaultSigner, vmID, "assertionMethod", resolverServer.URL)
	if err != nil {
		t.Fatalf("AddECDSAProof error: %v", err)
	}

	proofObj, ok := m["proof"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected proof to be a map, got %T", m["proof"])
	}
	pv, _ := proofObj["proofValue"].(string)
	if len(pv) != hex.EncodedLen(65) {
		t.Fatalf("expected proofValue hex length %d, got %d", hex.EncodedLen(65), len(pv))
	}
}

func TestJSONMap_AddECDSAProof_RejectsInvalidSignatureLength(t *testing.T) {
	m := JSONMap{
		"issuer": "did:example:issuer",
		"type":   "VerifiableCredential",
	}

	err := (&m).AddECDSAProof(&fakeSigner{sig: make([]byte, 66)}, "did:example:issuer#key-1", "assertionMethod", "https://example.invalid")
	if err == nil {
		t.Fatalf("expected error for invalid signature length")
	}
}

type fakeSigner struct {
	sig []byte
}

func (s *fakeSigner) Sign(hashPayload []byte) ([]byte, error) {
	if len(hashPayload) != 32 {
		return nil, fmt.Errorf("invalid signing digest length: got %d, want 32", len(hashPayload))
	}
	return s.sig, nil
}
