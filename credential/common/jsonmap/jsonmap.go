package jsonmap

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/pilacorp/go-credential-sdk/credential/common/bbs"
	"github.com/pilacorp/go-credential-sdk/credential/common/crypto"
	"github.com/pilacorp/go-credential-sdk/credential/common/dto"
	"github.com/pilacorp/go-credential-sdk/credential/common/processor"
	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	"github.com/pilacorp/go-credential-sdk/credential/common/util"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
)

// JSONMap represents a JSON object as a map.
type JSONMap map[string]interface{}

const (
	proofField string = "proof"

	JwtProof2020                string = "JwtProof2020"
	EcdsaSecp256k1Signature2019 string = "EcdsaSecp256k1Signature2019"
	DataIntegrityProof          string = "DataIntegrityProof"
	ECDSARDFC2019               string = "ecdsa-rdfc-2019"
	ECDSASECPKEY                string = "EcdsaSecp256k1VerificationKey2019"
)

// ToJSON serializes the JSONMap to JSON.
func (m *JSONMap) ToJSON() ([]byte, error) {
	if m == nil {
		return nil, fmt.Errorf("JSONMap is nil")
	}

	data, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JSONMap: %w", err)
	}

	var temp JSONMap
	if err := json.Unmarshal(data, &temp); err != nil {
		return nil, fmt.Errorf("failed to validate serialization: %w", err)
	}
	return data, nil
}

func (m *JSONMap) ToMap() (map[string]interface{}, error) {
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JSONMap: %w", err)
	}

	var data map[string]interface{}
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSONMap: %w", err)
	}

	return data, nil
}

// Canonicalize canonicalizes the JSONMap for signing or verification, excluding the proof field.
func (m *JSONMap) Canonicalize() ([]byte, error) {
	mCopy := make(JSONMap)
	for k, v := range *m {
		if k != proofField {
			mCopy[k] = v
		}
	}

	encoded, err := json.Marshal(mCopy)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JSONMap copy: %w", err)
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(encoded, &doc); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSONMap copy: %w", err)
	}

	canonicalDoc, err := processor.CanonicalizeDocument(doc)
	if err != nil {
		return nil, fmt.Errorf("failed to canonicalize document: %w", err)
	}

	return processor.ComputeDigest(canonicalDoc)
}

// CanonicalizeFull canonicalizes the full JSONMap, including the proof field,
// and returns its SHA-256 digest. Unlike Canonicalize, nothing is excluded.
func (m *JSONMap) CanonicalizeFull() ([]byte, error) {
	encoded, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JSONMap: %w", err)
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(encoded, &doc); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSONMap: %w", err)
	}

	canonicalDoc, err := processor.CanonicalizeDocument(doc)
	if err != nil {
		return nil, fmt.Errorf("failed to canonicalize document: %w", err)
	}

	return processor.ComputeDigest(canonicalDoc)
}

// AddECDSAProof adds an ECDSA proof to the JSONMap. verificationMethod must
// be a full DID URL (caller's responsibility to resolve/normalize).
func (m *JSONMap) AddECDSAProof(signerProvider signer.SignerProvider, verificationMethod, proofPurpose string) error {
	if m == nil {
		return fmt.Errorf("jsonmap: JSONMap is nil")
	}
	if signerProvider == nil {
		return fmt.Errorf("jsonmap: signer provider cannot be nil")
	}
	if verificationMethod == "" {
		return fmt.Errorf("jsonmap: verification method is required")
	}
	if proofPurpose == "" {
		return fmt.Errorf("jsonmap: proof purpose is required")
	}

	proof := &dto.Proof{
		Type:               DataIntegrityProof,
		Created:            time.Now().UTC().Format(time.RFC3339),
		VerificationMethod: verificationMethod,
		ProofPurpose:       proofPurpose,
		Cryptosuite:        ECDSARDFC2019,
	}

	signData, err := m.Canonicalize()
	if err != nil {
		return fmt.Errorf("jsonmap: failed to canonicalize JSONMap: %w", err)
	}

	if len(signData) != 32 {
		return fmt.Errorf("jsonmap: invalid signing digest length: got %d, want 32", len(signData))
	}

	signature, err := signerProvider.Sign(signData)
	if err != nil {
		return fmt.Errorf("jsonmap: failed to sign digest: %w", err)
	}
	// Guard against a mis-routed non-secp256k1 signer bound to an ecdsa-rdfc-2019
	// verification method: a secp256k1 ECDSA signature is 64 or 65 bytes.
	if l := len(signature); l != 64 && l != 65 {
		return fmt.Errorf("jsonmap: ecdsa-rdfc-2019 expects a 64/65-byte secp256k1 signature but the signer returned %d bytes; the signer does not match the verification method — pin the right VM with WithVerificationMethodKey", l)
	}
	proof.ProofValue = hex.EncodeToString(signature)
	m.appendProof(*proof)

	return nil
}

// AddCustomProof adds custom proof to the JSONMap.
func (m *JSONMap) AddCustomProof(proof *dto.Proof) error {
	if m == nil {
		return fmt.Errorf("JSONMap is nil")
	}
	if proof == nil {
		return fmt.Errorf("proof is nil")
	}
	m.appendProof(*proof)

	return nil
}

// VerifyProof verifies the JSONMap's proof(s). It also runs the strict-purpose
// check: rejects proofs whose VM has a hard revocation reason, was revoked
// before proof.created, or is missing from the relationship array for
// proof.proofPurpose.
//
// When targetVM is empty, every proof in the set must verify (W3C proof set,
// AND semantics). When targetVM is a verification method URL, only the proof
// bound to that VM is verified (the others are ignored); an error is returned
// if no proof uses targetVM.
//
// resolver is required; callers must construct it (e.g. via
// verificationmethod.NewHTTPResolver(baseURL)) before invoking VerifyProof.
func (m *JSONMap) VerifyProof(resolver verificationmethod.ResolverProvider, targetVM string, bbsEngine bbs.Engine) (bool, error) {
	if m == nil {
		return false, fmt.Errorf("JSONMap is nil")
	}
	if resolver == nil {
		return false, fmt.Errorf("document resolver is required")
	}

	proofs, err := m.allProofs()
	if err != nil {
		return false, fmt.Errorf("failed to parse proof: %w", err)
	}
	if len(proofs) == 0 {
		return false, fmt.Errorf("credential has no proof")
	}

	// Verify a single, caller-selected proof.
	if targetVM != "" {
		for i := range proofs {
			if proofs[i].VerificationMethod == targetVM {
				ok, err := m.verifyOneProof(resolver, &proofs[i], bbsEngine)
				if err != nil {
					return false, fmt.Errorf("proof (%s): %w", targetVM, err)
				}
				return ok, nil
			}
		}
		return false, fmt.Errorf("no proof found for verification method %q", targetVM)
	}

	// W3C proof set: every proof must verify, each against its own
	// verification method.
	for i := range proofs {
		ok, err := m.verifyOneProof(resolver, &proofs[i], bbsEngine)
		if err != nil {
			return false, fmt.Errorf("proof %d (%s): %w", i, proofs[i].VerificationMethod, err)
		}
		if !ok {
			return false, nil
		}
	}
	return true, nil
}

// verifyOneProof verifies a single proof against the DID document resolved from
// that proof's own verification method.
func (m *JSONMap) verifyOneProof(resolver verificationmethod.ResolverProvider, proof *dto.Proof, bbsEngine bbs.Engine) (bool, error) {
	signerDID, err := m.didForProof(proof)
	if err != nil {
		return false, err
	}
	doc, err := resolver.ResolveDocument(context.Background(), signerDID)
	if err != nil {
		return false, fmt.Errorf("failed to resolve DID document for '%s': %w", signerDID, err)
	}

	// Data Integrity proof configuration: a present `created` MUST be a valid
	// datetime, otherwise the document is non-conforming and verification fails.
	if proof.Type == DataIntegrityProof && proof.Created != "" {
		if _, err := util.ParseTimeWrapper(proof.Created); err != nil {
			return false, fmt.Errorf("invalid proof created datetime %q: %w", proof.Created, err)
		}
	}

	switch {
	case proof.Type == JwtProof2020:
		return m.verifyJWTProof(doc, proof)

	case proof.Type == EcdsaSecp256k1Signature2019 || proof.Type == ECDSASECPKEY:
		return m.verifyEcdsaProofLegacy()

	case proof.Type == DataIntegrityProof && proof.Cryptosuite == ECDSARDFC2019:
		return m.verifyDataIntegrityProof(doc, proof)

	case proof.Type == DataIntegrityProof && proof.Cryptosuite == ECDSASD2023:
		return m.verifyECDSASDProof(doc, proof)

	case proof.Type == DataIntegrityProof && proof.Cryptosuite == bbs.Cryptosuite:
		return m.verifyBBSProof(doc, proof, bbsEngine)

	case proof.Type == JsonWebSignature2020:
		return m.verifyJWSProof(doc, proof)

	default:
		return false, fmt.Errorf("unsupported proof type: %s", proof.Type)
	}
}

// didForProof returns the DID to resolve for a proof: the DID embedded in the
// proof's verificationMethod when present, otherwise the body's issuer/holder.
func (m *JSONMap) didForProof(proof *dto.Proof) (string, error) {
	if did := didFromVMURL(proof.VerificationMethod); did != "" {
		return did, nil
	}
	return signerDIDFromBody(*m)
}

// didFromVMURL extracts the DID prefix from a verification method URL
// ("did:x:y#key-1" → "did:x:y"); returns "" when vm is not a DID URL.
func didFromVMURL(vm string) string {
	if !strings.HasPrefix(vm, "did:") {
		return ""
	}
	if i := strings.IndexByte(vm, '#'); i > 0 {
		return vm[:i]
	}
	return vm
}

// verifyECDSA verifies an ECDSA-signed JSONMap.
func (m *JSONMap) verifyECDSA(publicKey string, proof *dto.Proof) (bool, error) {
	doc, err := m.Canonicalize()
	if err != nil {
		return false, fmt.Errorf("failed to canonicalize JSONMap: %w", err)
	}

	return crypto.ECDSAVerifySignature(publicKey, proof.ProofValue, doc)
}

func (m *JSONMap) verifyJWTProof(doc *verificationmethod.DIDDocument, proof *dto.Proof) (bool, error) {
	vmURL, err := jwtVerificationMethodURL((*m))
	if err != nil {
		return false, err
	}
	vm, err := verificationmethod.FindVerificationMethod(doc, vmURL)
	if err != nil {
		return false, fmt.Errorf("failed to resolve verification method: %w", err)
	}
	publicKey, err := publicKeyHexFromVM(vm)
	if err != nil {
		return false, err
	}

	ok, err := crypto.VerifyJwtProof((*map[string]interface{})(m), publicKey)
	if err != nil || !ok {
		return ok, err
	}
	if err := strictPurposeCheck(doc, vm, "assertionMethod", proof.Created); err != nil {
		return false, err
	}
	return true, nil
}

func (m *JSONMap) verifyDataIntegrityProof(doc *verificationmethod.DIDDocument, proof *dto.Proof) (bool, error) {
	vm, err := verificationmethod.FindVerificationMethod(doc, proof.VerificationMethod)
	if err != nil {
		return false, fmt.Errorf("failed to resolve verification method: %w", err)
	}
	publicKey, err := publicKeyHexFromVM(vm)
	if err != nil {
		return false, err
	}

	ok, err := m.verifyECDSA(publicKey, proof)
	if err != nil || !ok {
		return ok, err
	}
	if err := strictPurposeCheck(doc, vm, proof.ProofPurpose, proof.Created); err != nil {
		return false, err
	}
	return true, nil
}

// verifyEcdsaProofLegacy verifies an ECDSA-signed JSONMap. Supports legacy
// VC for compatibility.
func (m *JSONMap) verifyEcdsaProofLegacy() (bool, error) {
	proofMap, ok := m.getFirstProof().(map[string]interface{})
	if !ok {
		return false, fmt.Errorf("proof is missing or has unexpected format")
	}

	proofValue, ok := proofMap["proofValue"].(string)
	if !ok || proofValue == "" {
		return false, fmt.Errorf("proof value is missing or invalid in the request")
	}
	publicKeyHex, ok := proofMap["verificationMethod"].(string)
	if !ok || publicKeyHex == "" {
		return false, fmt.Errorf("proof verificationMethod is missing or invalid in the request")
	}

	signatureBytes, err := hex.DecodeString(proofValue)
	if err != nil {
		return false, fmt.Errorf("failed to decode proof value to bytes: %w", err)
	}

	reqCopy := make(map[string]interface{})

	for k, v := range *m {
		if k != proofField {
			reqCopy[k] = v
		}
	}

	message, err := json.Marshal(reqCopy)
	if err != nil {
		return false, fmt.Errorf("failed to marshal request to JSON: %w", err)
	}

	pubBytes, err := crypto.KeyToBytes(publicKeyHex)
	if err != nil {
		return false, fmt.Errorf("failed to convert public key to bytes: %w", err)
	}

	verified := crypto.VerifyJSONSignature(pubBytes, message, signatureBytes)

	return verified, nil
}

// ===== Helpers (internal) =====

func (m *JSONMap) getFirstProof() interface{} {
	if raw, ok := (*m)[proofField]; ok {
		if arr, ok := raw.([]interface{}); ok && len(arr) > 0 {
			return arr[0]
		}
		return raw
	}
	return nil
}

// allProofs parses every proof on the JSONMap (single object or array).
func (m *JSONMap) allProofs() ([]dto.Proof, error) {
	list := m.rawProofList()
	out := make([]dto.Proof, 0, len(list))
	for _, raw := range list {
		p, err := ParseRawToProof(raw)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// rawProofList normalizes the proof field into a slice of raw proof entries,
// accepting a single object, []interface{}, or []map[string]interface{}.
func (m *JSONMap) rawProofList() []interface{} {
	raw, ok := (*m)[proofField]
	if !ok || raw == nil {
		return nil
	}
	switch v := raw.(type) {
	case []interface{}:
		return v
	case []map[string]interface{}:
		out := make([]interface{}, len(v))
		for i := range v {
			out[i] = v[i]
		}
		return out
	default:
		return []interface{}{raw}
	}
}

// appendProof appends a proof, preserving existing proofs (W3C proof set). A
// lone proof is stored as an object; multiple proofs as an array.
func (m *JSONMap) appendProof(p dto.Proof) {
	list := append(m.rawProofList(), util.SerializeProofs([]dto.Proof{p}))
	if len(list) == 1 {
		(*m)[proofField] = list[0]
	} else {
		(*m)[proofField] = list
	}
}

// ParseRawToProof converts a JSON object to a Proof struct.
func ParseRawToProof(proof interface{}) (dto.Proof, error) {
	var result dto.Proof
	if proof == nil {
		return result, fmt.Errorf("JSONMap has no proof")
	}
	proofMap, ok := proof.(map[string]interface{})
	if !ok {
		return result, fmt.Errorf("invalid proof format: expected map[string]interface{}, got %T", proof)
	}

	if t, ok := proofMap["type"].(string); ok {
		result.Type = t
	}
	if created, ok := proofMap["created"].(string); ok {
		result.Created = created
	}
	if purpose, ok := proofMap["proofPurpose"].(string); ok {
		result.ProofPurpose = purpose
	}
	if vm, ok := proofMap["verificationMethod"].(string); ok {
		result.VerificationMethod = vm
	}
	if pv, ok := proofMap["proofValue"].(string); ok {
		result.ProofValue = pv
	}
	if pv, ok := proofMap["cryptosuite"].(string); ok {
		result.Cryptosuite = pv
	}
	if jws, ok := proofMap["jws"].(string); ok {
		result.JWS = jws
	}

	return result, nil
}

// signerDIDFromBody returns the DID of the entity that signed the JSONMap.
// VCs put it in `issuer`, VPs in `holder`; both forms accept either a plain
// string DID or an object with an `id` field per W3C VC Data Model. Returns
// an error when neither key is present so the verifier never silently falls
// back to extracting a DID from the proof field.
func signerDIDFromBody(m map[string]interface{}) (string, error) {
	if did, ok := DIDFromField(m["issuer"]); ok {
		return did, nil
	}
	if did, ok := DIDFromField(m["holder"]); ok {
		return did, nil
	}
	return "", fmt.Errorf("body is missing required `issuer` (VC) or `holder` (VP) field")
}

// DIDFromField accepts either a plain string DID or an object form
// `{"id": "did:..."}` (per W3C VC Data Model) and returns the DID when present.
// Shared by the signing and verification paths so both accept the same issuer
// shapes.
func DIDFromField(v interface{}) (string, bool) {
	switch t := v.(type) {
	case string:
		if t != "" {
			return t, true
		}
	case map[string]interface{}:
		if id, ok := t["id"].(string); ok && id != "" {
			return id, true
		}
	}
	return "", false
}

// strictPurposeCheck enforces the post-crypto checks for multi-VM:
//  1. Hard revocation reason → reject (key compromised, all signatures invalid).
//  2. Revoked timestamp set and proof.created on/after revoked → reject.
//  3. VM id missing from the relationship array for proofPurpose → reject.
//
// Order is significant: hard reasons short-circuit before the timestamp
// comparison so the verifier returns the strongest failure reason first.
func strictPurposeCheck(doc *verificationmethod.DIDDocument, vm *verificationmethod.VerificationMethodEntry, proofPurpose, proofCreated string) error {
	if verificationmethod.IsHardRevocationReason(vm.RevocationReason) {
		return fmt.Errorf("verification method '%s' revoked with hard reason '%s'", vm.ID, vm.RevocationReason)
	}

	if vm.Revoked != nil {
		createdTW, err := util.ParseTimeWrapper(proofCreated)
		if err != nil {
			return fmt.Errorf("invalid proof.created timestamp '%s': %w", proofCreated, err)
		}
		created := createdTW.Time
		if !created.Before(*vm.Revoked) {
			return fmt.Errorf("verification method '%s' was revoked at %s; proof.created %s is not earlier",
				vm.ID, vm.Revoked.UTC().Format(time.RFC3339), created.UTC().Format(time.RFC3339))
		}
	}

	var arr []string
	switch proofPurpose {
	case "authentication":
		arr = doc.Authentication
	case "assertionMethod":
		arr = doc.AssertionMethod
	default:
		return fmt.Errorf("unsupported proofPurpose '%s'", proofPurpose)
	}
	if !idInArray(vm.ID, doc.ID, arr) {
		return fmt.Errorf("verification method '%s' is not granted purpose '%s' on DID '%s'",
			vm.ID, proofPurpose, doc.ID)
	}
	return nil
}

// idInArray reports whether vm.ID (full URL or fragment) appears in arr.
func idInArray(vmID, docID string, arr []string) bool {
	frag := vmID
	if i := len(docID); len(vmID) > i && vmID[:i] == docID && vmID[i] == '#' {
		frag = vmID[i:]
	}
	for _, ref := range arr {
		if ref == vmID || ref == frag {
			return true
		}
	}
	return false
}

// publicKeyHexFromVM extracts the hex public key from the VM, supporting
// both publicKeyHex and publicKeyJwk encodings.
func publicKeyHexFromVM(vm *verificationmethod.VerificationMethodEntry) (string, error) {
	if vm == nil {
		return "", fmt.Errorf("verification method is nil")
	}
	if vm.PublicKeyHex != "" {
		return stripHexPrefix(vm.PublicKeyHex), nil
	}
	if vm.PublicKeyJwk != nil {
		return verificationmethod.JWKToHex(vm.PublicKeyJwk)
	}
	return "", fmt.Errorf("verification method '%s' has no public key material", vm.ID)
}

func stripHexPrefix(s string) string {
	if len(s) >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		return s[2:]
	}
	return s
}

// jwtVerificationMethodURL returns the verification method URL for a JWT proof.
func jwtVerificationMethodURL(m map[string]interface{}) (string, error) {
	if proofMap, ok := m["proof"].(map[string]interface{}); ok {
		if vm, ok := proofMap["verificationMethod"].(string); ok && vm != "" {
			return vm, nil
		}
		if jws, ok := proofMap["jws"].(string); ok && jws != "" {
			if kid, ok := jwsKid(jws); ok && kid != "" {
				return kid, nil
			}
		}
	}
	return "", fmt.Errorf("token is missing verification method id (kid/verificationMethod)")
}

// jwsKid pulls the kid claim out of the JWS header (first segment of a
// compact JWS, base64url-encoded JSON).
func jwsKid(jws string) (string, bool) {
	dot := -1
	for i := 0; i < len(jws); i++ {
		if jws[i] == '.' {
			dot = i
			break
		}
	}
	if dot <= 0 {
		return "", false
	}
	headerB64 := jws[:dot]
	headerBytes, err := base64.RawURLEncoding.DecodeString(headerB64)
	if err != nil {
		return "", false
	}
	var hdr struct {
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerBytes, &hdr); err != nil {
		return "", false
	}
	return hdr.Kid, hdr.Kid != ""
}
