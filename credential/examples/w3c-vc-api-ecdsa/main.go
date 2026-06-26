// Command w3c-vc-api-ecdsa is a minimal VC API server exposing this module's
// ecdsa-sd-2023 implementation for the w3c/vc-di-ecdsa-test-suite.
//
//	POST /credentials/issue   {credential, options.mandatoryPointers}  -> {verifiableCredential}
//	POST /credentials/derive  {verifiableCredential, options.selectivePointers} -> {verifiableCredential}
//	POST /credentials/verify  {verifiableCredential}                    -> 200 / 400
//
// The issuer key is a P-256 key surfaced as a self-resolving did:key, so no
// external DID resolver is needed.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/mr-tron/base58"

	"github.com/pilacorp/go-credential-sdk/credential/common/jsonmap"
	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	vm "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
)

// p256MulticodecPrefix is varint(0x1200) — the multicodec for a p256-pub key.
var p256MulticodecPrefix = []byte{0x80, 0x24}

// didKeyFromP256 encodes a P-256 public key as a did:key plus its multibase key
// string (the part after "did:key:", also used as the VM fragment).
func didKeyFromP256(pub *ecdsa.PublicKey) (did, multibaseKey string) {
	compressed := elliptic.MarshalCompressed(elliptic.P256(), pub.X, pub.Y)
	raw := append(append([]byte{}, p256MulticodecPrefix...), compressed...)
	multibaseKey = "z" + base58.Encode(raw)
	return "did:key:" + multibaseKey, multibaseKey
}

// p256FromDIDKey decodes the P-256 public key from a did:key (with or without a
// "#fragment"), returning the key and the multibase key string.
func p256FromDIDKey(did string) (*ecdsa.PublicKey, string, error) {
	s := strings.TrimPrefix(did, "did:key:")
	if i := strings.IndexByte(s, '#'); i >= 0 {
		s = s[:i]
	}
	if !strings.HasPrefix(s, "z") {
		return nil, "", fmt.Errorf("did:key: expected base58btc 'z' multibase: %q", did)
	}
	raw, err := base58.Decode(s[1:])
	if err != nil {
		return nil, "", fmt.Errorf("did:key: decode multibase: %w", err)
	}
	if len(raw) < len(p256MulticodecPrefix) || raw[0] != p256MulticodecPrefix[0] || raw[1] != p256MulticodecPrefix[1] {
		return nil, "", fmt.Errorf("did:key: not a p256-pub multikey: %q", did)
	}
	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), raw[len(p256MulticodecPrefix):])
	if x == nil {
		return nil, "", fmt.Errorf("did:key: invalid P-256 point: %q", did)
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, s, nil
}

// didKeyResolver resolves any P-256 did:key into a DID document with a single
// JsonWebKey2020 verification method (in assertionMethod + authentication).
type didKeyResolver struct{}

func (didKeyResolver) ResolveDocument(_ context.Context, did string) (*vm.DIDDocument, error) {
	pub, multibaseKey, err := p256FromDIDKey(did)
	if err != nil {
		return nil, err
	}
	base := "did:key:" + multibaseKey
	return vm.NewDIDDocument(base, vm.NewP256VM(base, multibaseKey, pub)), nil
}

type server struct {
	issuer   *signer.P256Provider
	issuerVM string // did:key:z...#z...
	resolver vm.ResolverProvider
}

func main() {
	issuerHex := os.Getenv("ISSUER_P256_HEX")
	if issuerHex == "" {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			log.Fatalf("generate issuer key: %v", err)
		}
		b := make([]byte, 32)
		priv.D.FillBytes(b)
		issuerHex = hex.EncodeToString(b)
	}

	prov, err := signer.NewP256ProviderFromHex(issuerHex)
	if err != nil {
		log.Fatalf("load issuer key: %v", err)
	}
	issuerDID, multibaseKey := didKeyFromP256(prov.Public())

	s := &server{
		issuer:   prov,
		issuerVM: issuerDID + "#" + multibaseKey,
		resolver: didKeyResolver{},
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	http.HandleFunc("/credentials/issue", s.handleIssue)
	http.HandleFunc("/credentials/derive", s.handleDerive)
	http.HandleFunc("/credentials/verify", s.handleVerify)

	printStartupConfig(issuerDID, issuerHex, port)

	log.Printf("listening on :%s", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatal(err)
	}
}

func (s *server) handleIssue(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Credential json.RawMessage `json:"credential"`
		Options    struct {
			MandatoryPointers []string `json:"mandatoryPointers"`
		} `json:"options"`
	}
	if err := decode(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	var m jsonmap.JSONMap
	if err := json.Unmarshal(body.Credential, &m); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("parse credential: %w", err))
		return
	}

	if err := (&m).AddECDSASDBaseProof(s.issuer, s.issuerVM, "assertionMethod", body.Options.MandatoryPointers); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("issue: %w", err))
		return
	}

	writeJSON(w, http.StatusCreated, map[string]interface{}{"verifiableCredential": m})
}

func (s *server) handleDerive(w http.ResponseWriter, r *http.Request) {
	var body struct {
		VerifiableCredential json.RawMessage `json:"verifiableCredential"`
		Options              struct {
			SelectivePointers []string `json:"selectivePointers"`
		} `json:"options"`
	}
	if err := decode(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	var m jsonmap.JSONMap
	if err := json.Unmarshal(body.VerifiableCredential, &m); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("parse verifiableCredential: %w", err))
		return
	}

	derived, err := (&m).DeriveECDSASD(body.Options.SelectivePointers)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("derive: %w", err))
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"verifiableCredential": derived})
}

func (s *server) handleVerify(w http.ResponseWriter, r *http.Request) {
	var body struct {
		VerifiableCredential json.RawMessage `json:"verifiableCredential"`
	}
	if err := decode(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	var m jsonmap.JSONMap
	if err := json.Unmarshal(body.VerifiableCredential, &m); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("parse verifiableCredential: %w", err))
		return
	}

	ok, err := (&m).VerifyProof(s.resolver, "", nil)
	if err != nil || !ok {
		if err == nil {
			err = fmt.Errorf("proof invalid")
		}
		writeError(w, http.StatusBadRequest, fmt.Errorf("verification failed: %w", err))
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"checks": []string{"proof"}, "verified": true})
}

// --- helpers ---

func decode(r *http.Request, v interface{}) error {
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		return fmt.Errorf("invalid JSON body: %w", err)
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]interface{}{"errors": []string{err.Error()}})
}

func printStartupConfig(issuerDID, issuerHex, port string) {
	fmt.Printf("\nissuer did:key : %s\n", issuerDID)
	fmt.Printf("ISSUER_P256_HEX: %s   (set this env var to keep the key across restarts)\n\n", issuerHex)
	fmt.Printf("Paste into vc-di-ecdsa-test-suite/localConfig.cjs:\n\n")
	fmt.Printf(`module.exports = {
  settings: {},
  implementations: [{
    name: 'go-credential-sdk',
    implementation: 'go-credential-sdk',
    issuers: [{
      id: '%s',
      endpoint: 'http://localhost:%s/credentials/issue',
      supportedEcdsaKeyTypes: ['P-256'],
      tags: ['ecdsa-sd-2023'],
    }],
    verifiers: [{
      id: 'go-credential-sdk',
      endpoint: 'http://localhost:%s/credentials/verify',
      supportedEcdsaKeyTypes: ['P-256'],
      tags: ['ecdsa-sd-2023'],
    }],
    vcHolders: [{
      id: 'go-credential-sdk',
      endpoint: 'http://localhost:%s/credentials/derive',
      supportedEcdsaKeyTypes: ['P-256'],
      tags: ['vcHolder'],
    }],
  }],
};
`, issuerDID, port, port, port)
	fmt.Println()
}
