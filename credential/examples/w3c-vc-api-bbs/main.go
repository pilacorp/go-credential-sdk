// Command w3c-vc-api-bbs is a minimal VC API server exposing this module's
// bbs-2023 implementation for the w3c/vc-di-bbs-test-suite.
//
//	POST /credentials/issue   {credential, options.mandatoryPointers}  -> {verifiableCredential}
//	POST /credentials/derive  {verifiableCredential, options.selectivePointers} -> {verifiableCredential}
//	POST /credentials/verify  {verifiableCredential}                    -> 200 / 400
//
// The issuer key is a BLS12-381 G2 key surfaced as a self-resolving did:key, so
// no external DID resolver is needed.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/pilacorp/go-credential-sdk/credential/common/bbs"
	"github.com/pilacorp/go-credential-sdk/credential/common/jsonmap"
	vm "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
)

// defaultIssuerHex is a known-valid BLS12-381 scalar (the W3C spec example issuer
// key); override with ISSUER_BBS_HEX to use a different key.
const defaultIssuerHex = "66d36e118832af4c5e28b2dfe1b9577857e57b042a33e06bdea37b811ed09ee0"

// bbsDIDKeyResolver resolves any BLS12-381 G2 did:key into a DID document with a
// single Multikey verification method.
type bbsDIDKeyResolver struct{}

func (bbsDIDKeyResolver) ResolveDocument(_ context.Context, did string) (*vm.DIDDocument, error) {
	s := strings.TrimPrefix(did, "did:key:")
	if i := strings.IndexByte(s, '#'); i >= 0 {
		s = s[:i]
	}
	if !strings.HasPrefix(s, "z") {
		return nil, fmt.Errorf("did:key: expected base58btc 'z' multibase: %q", did)
	}
	if _, err := bbs.DecodePublicKeyMultibase(s); err != nil {
		return nil, fmt.Errorf("did:key: not a BLS12-381 G2 multikey: %w", err)
	}
	base := "did:key:" + s
	return vm.NewDIDDocument(base, vm.NewBLS12381G2VM(base, s, s)), nil
}

type server struct {
	signer   bbs.Signer
	engine  bbs.Engine
	issuerVM string // did:key:z...#z...
	resolver vm.ResolverProvider
}

func main() {
	issuerHex := os.Getenv("ISSUER_BBS_HEX")
	if issuerHex == "" {
		issuerHex = defaultIssuerHex
	}

	signer, err := bbs.NewZKryptiumSignerFromPrivateKeyHex(issuerHex)
	if err != nil {
		log.Fatalf("load issuer key: %v", err)
	}
	multibaseKey := bbs.EncodePublicKeyMultibase(signer.PublicKey())
	issuerDID := "did:key:" + multibaseKey

	s := &server{
		signer:   signer,
		engine:  bbs.NewZKryptiumEngine(),
		issuerVM: issuerDID + "#" + multibaseKey,
		resolver: bbsDIDKeyResolver{},
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

	if err := (&m).AddBBSBaseProof(s.signer, s.issuerVM, "assertionMethod", body.Options.MandatoryPointers); err != nil {
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

	derived, err := (&m).DeriveBBS(body.Options.SelectivePointers, nil, s.engine)
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

	ok, err := (&m).VerifyProof(s.resolver, "", s.engine)
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
	fmt.Printf("ISSUER_BBS_HEX : %s   (set this env var to keep the key across restarts)\n\n", issuerHex)
	fmt.Printf("Paste into vc-di-bbs-test-suite/localConfig.cjs:\n\n")
	fmt.Printf(`module.exports = {
  settings: {},
  implementations: [{
    name: 'go-credential-sdk',
    implementation: 'go-credential-sdk',
    issuers: [{
      id: '%s',
      endpoint: 'http://localhost:%s/credentials/issue',
      tags: ['bbs-2023'],
    }],
    verifiers: [{
      id: 'go-credential-sdk',
      endpoint: 'http://localhost:%s/credentials/verify',
      tags: ['bbs-2023'],
    }],
    vcHolders: [{
      id: 'go-credential-sdk',
      endpoint: 'http://localhost:%s/credentials/derive',
      tags: ['vcHolder', 'bbs-2023'],
    }],
  }],
};
`, issuerDID, port, port, port)
	fmt.Println()
}
