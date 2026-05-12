package jsonmap

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

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
	// Marshal the JSONMap to bytes
	bytes, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JSONMap: %w", err)
	}

	// Unmarshal the bytes to a map
	var data map[string]interface{}
	if err := json.Unmarshal(bytes, &data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSONMap: %w", err)
	}

	return data, nil
}

// Canonicalize canonicalizes the JSONMap for signing or verification, excluding the proof field.
func (m *JSONMap) Canonicalize() ([]byte, error) {
	mCopy := make(JSONMap)
	for k, v := range *m {
		if k != "proof" {
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

// AddECDSAProof adds an ECDSA proof to the JSONMap.
func (m *JSONMap) AddECDSAProof(signerProvider signer.SignerProvider, verificationMethod, proofPurpose, didBaseURL string) error {
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
	if err := signer.ValidateSignatureLength(signature); err != nil {
		return fmt.Errorf("jsonmap: %w", err)
	}
	proof.ProofValue = hex.EncodeToString(signature)
	(*m)["proof"] = util.SerializeProofs([]dto.Proof{*proof})

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
	(*m)["proof"] = util.SerializeProofs([]dto.Proof{*proof})

	return nil
}

// parseRawToProof converts a JSON object to a Proof struct.
func ParseRawToProof(proof interface{}) (dto.Proof, error) {
	var result dto.Proof
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

	return result, nil
}

// VerifyProofOptions controls optional verifier behavior. The zero value
// represents the SDK defaults: strict proofPurpose checking is ON.
type VerifyProofOptions struct {
	StrictProofPurpose bool
	Resolver           verificationmethod.ResolverProvider
}

// VerifyProofOpt mutates VerifyProofOptions.
type VerifyProofOpt func(*VerifyProofOptions)

// WithResolverProvider overrides the default HTTP resolver used by VerifyProof.
// This enables offline tests or custom resolver implementations.
func WithResolverProvider(r verificationmethod.ResolverProvider) VerifyProofOpt {
	return func(o *VerifyProofOptions) {
		o.Resolver = r
	}
}

// WithStrictProofPurpose toggles whether the verifier rejects credentials
// whose verification method is not listed in the relationship array for
// the proof's purpose, or has been revoked. Default ON. Pass false only
// for emergency rollback (matches the STRICT_PROOF_PURPOSE flag used in
// downstream services).
func WithStrictProofPurpose(strict bool) VerifyProofOpt {
	return func(o *VerifyProofOptions) {
		o.StrictProofPurpose = strict
	}
}

func defaultVerifyProofOptions() *VerifyProofOptions {
	return &VerifyProofOptions{StrictProofPurpose: true}
}

// VerifyProof verifies an ECDSA-signed JSONMap. When the strict-purpose
// option is enabled (default), the verifier additionally rejects proofs
// whose VM has a hard revocation reason, was revoked before proof.created,
// or is missing from the relationship array for proof.proofPurpose.
func (m *JSONMap) VerifyProof(didBaseURL string, opts ...VerifyProofOpt) (bool, error) {
	if m == nil {
		return false, fmt.Errorf("JSONMap is nil")
	}

	options := defaultVerifyProofOptions()
	for _, opt := range opts {
		opt(options)
	}

	proofs, ok := (*m)["proof"].([]interface{})
	if !ok {
		if proof, exists := (*m)["proof"]; exists {
			proofs = []interface{}{proof}
		} else {
			return false, fmt.Errorf("JSONMap has no proof")
		}
	}
	proof, err := ParseRawToProof(proofs[0])
	if err != nil {
		return false, fmt.Errorf("failed to parse proof: %w", err)
	}

	resolver := options.Resolver
	if resolver == nil {
		resolver = verificationmethod.NewHTTPResolver(didBaseURL)
	}

	// Resolve the document by the signer DID claimed in the body — `issuer`
	// for VCs, `holder` for VPs. This is the authoritative source: we trust
	// what the signed payload says about who created it, then verify the kid
	// referenced in the proof actually belongs to that DID's document.
	signerDID, err := signerDIDFromBody(*m)
	if err != nil {
		return false, err
	}
	doc, err := resolver.ResolveDocument(context.Background(), signerDID)
	if err != nil {
		return false, fmt.Errorf("failed to resolve DID document for '%s': %w", signerDID, err)
	}

	if proof.Type == JwtProof2020 {
		vmURL, err := jwtVerificationMethodURL((*m), signerDID)
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

		ok2, err := crypto.VerifyJwtProof((*map[string]interface{})(m), publicKey)
		if err != nil || !ok2 {
			return ok2, err
		}
		if options.StrictProofPurpose {
			if err := strictPurposeCheck(doc, vm, "assertionMethod", proof.Created); err != nil {
				return false, err
			}
		}
		return true, nil
	} else if proof.Type == EcdsaSecp256k1Signature2019 || proof.Type == ECDSASECPKEY {

		return m.verifyEcdsaProofLegacy()
	} else if proof.Type == DataIntegrityProof && proof.Cryptosuite == ECDSARDFC2019 {
		vm, err := verificationmethod.FindVerificationMethod(doc, proof.VerificationMethod)
		if err != nil {
			return false, fmt.Errorf("failed to resolve verification method: %w", err)
		}
		publicKey, err := publicKeyHexFromVM(vm)
		if err != nil {
			return false, err
		}

		ok2, err := m.verifyECDSA(publicKey, &proof)
		if err != nil || !ok2 {
			return ok2, err
		}
		if options.StrictProofPurpose {
			if err := strictPurposeCheck(doc, vm, proof.ProofPurpose, proof.Created); err != nil {
				return false, err
			}
		}
		return true, nil
	} else {

		return false, fmt.Errorf("unsupported proof type: %s", proof.Type)
	}
}

// signerDIDFromBody returns the DID of the entity that signed the JSONMap.
// VCs put it in `issuer`, VPs in `holder`; both forms accept either a plain
// string DID or an object with an `id` field per W3C VC Data Model. Returns
// an error when neither key is present so the verifier never silently falls
// back to extracting a DID from the proof field.
func signerDIDFromBody(m map[string]interface{}) (string, error) {
	if did, ok := didFromField(m["issuer"]); ok {
		return did, nil
	}
	if did, ok := didFromField(m["holder"]); ok {
		return did, nil
	}
	return "", fmt.Errorf("body is missing required `issuer` (VC) or `holder` (VP) field")
}

// didFromField accepts either a plain string DID or an object form
// `{"id": "did:..."}` and returns the DID string when present.
func didFromField(v interface{}) (string, bool) {
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
		created, err := time.Parse(time.RFC3339, proofCreated)
		if err != nil {
			return fmt.Errorf("invalid proof.created timestamp '%s': %w", proofCreated, err)
		}
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

// jwtVerificationMethodURL returns the verification method URL for a JWT
// proof. Preference order: explicit kid in the proof's JWS header → the
// proof's `verificationMethod` field → fall back to <issuer>#key-1 for
// legacy JWTs that carry neither.
func jwtVerificationMethodURL(m map[string]interface{}, issuerDID string) (string, error) {
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

// VerifyECDSA verifies an ECDSA-signed JSONMap.
func (m *JSONMap) verifyECDSA(publicKey string, proof *dto.Proof) (bool, error) {
	doc, err := m.Canonicalize()
	if err != nil {
		return false, fmt.Errorf("failed to canonicalize JSONMap: %w", err)
	}

	return crypto.ECDSAVerifySignature(publicKey, proof.ProofValue, doc)
}

// verifyEcdsaProofLegacy verifies an ECDSA-signed JSONMap.
// This function support lecacy VC for compatibility
func (m *JSONMap) verifyEcdsaProofLegacy() (bool, error) {

	proofValue, ok := (*m)["proof"].(map[string]interface{})["proofValue"].(string)
	if !ok || proofValue == "" {
		return false, fmt.Errorf("proof value is missing or invalid in the request")
	}
	publicKeyHex, ok := (*m)["proof"].(map[string]interface{})["verificationMethod"].(string)
	if !ok || publicKeyHex == "" {
		return false, fmt.Errorf("proof verificationMethod is missing or invalid in the request")
	}

	signatureBytes, err := hex.DecodeString(proofValue)
	if err != nil {
		return false, fmt.Errorf("failed to decode proof value to bytes: %w", err)
	}

	reqCopy := make(map[string]interface{})

	for k, v := range *m {
		if k != "proof" {
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
