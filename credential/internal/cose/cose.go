// Package cose implements the COSE_Sign1 structure (RFC 9052 §4.4) for
// securing Verifiable Credentials and Presentations per W3C VC-JOSE-COSE.
//
// It builds on github.com/fxamacker/cbor/v2 (already a dependency of the root
// module) and handles only what the credential layer needs: ES256 / ES256K
// signing and verification with an attached JSON payload.
package cose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"fmt"
	"math/big"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/fxamacker/cbor/v2"
)

// COSE header labels (RFC 9052 §3.1, IANA COSE Header Parameters).
const (
	HeaderAlg         = 1
	HeaderCrit        = 2 // Critical headers (RFC 9052 §3.1)
	HeaderContentType = 3
	HeaderKid         = 4
	HeaderTyp         = 16 // CoAP Content-Format / "typ" per RFC 9596
)

// COSE algorithm identifiers (IANA COSE Algorithms).
const (
	AlgES256  = -7  // ECDSA w/ SHA-256, P-256
	AlgES256K = -47 // ECDSA w/ SHA-256, secp256k1 (RFC 8812)
)

// Protected carries the COSE protected header fields the credential layer
// uses. It maps 1:1 to the CBOR map inside the protected-header bstr.
type Protected struct {
	Alg         int    // Label 1: algorithm identifier
	ContentType string // Label 3: e.g. "application/vc"
	Kid         string // Label 4: verification method DID URL
	Typ         string // Label 16: e.g. "application/vc+cose"
}

// encode serialises the protected header as a deterministic CBOR map.
// The W3C test vectors use integer-keyed maps in canonical order (1, 3, 4, 16).
func (p Protected) encode() ([]byte, error) {
	m := make(map[int]interface{}, 4)
	m[HeaderAlg] = p.Alg
	if p.ContentType != "" {
		m[HeaderContentType] = p.ContentType
	}
	if p.Kid != "" {
		// W3C test vectors encode kid as a bstr (CBOR byte string).
		m[HeaderKid] = []byte(p.Kid)
	}
	if p.Typ != "" {
		m[HeaderTyp] = p.Typ
	}
	return encMode.Marshal(m)
}

// decode parses a CBOR-encoded protected header map.
func decodeProtected(data []byte) (Protected, error) {
	var raw map[int]cbor.RawMessage
	if err := decMode.Unmarshal(data, &raw); err != nil {
		return Protected{}, fmt.Errorf("decode protected header: %w", err)
	}

	var p Protected

	if v, ok := raw[HeaderAlg]; ok {
		var alg int
		if err := decMode.Unmarshal(v, &alg); err != nil {
			return Protected{}, fmt.Errorf("decode alg: %w", err)
		}
		p.Alg = alg
	}

	if v, ok := raw[HeaderContentType]; ok {
		var ct string
		if err := decMode.Unmarshal(v, &ct); err != nil {
			return Protected{}, fmt.Errorf("decode content_type: %w", err)
		}
		p.ContentType = ct
	}

	if v, ok := raw[HeaderKid]; ok {
		// kid may be encoded as bstr or tstr; accept both.
		var kidBytes []byte
		if err := decMode.Unmarshal(v, &kidBytes); err != nil {
			// Try text string.
			var kidStr string
			if err2 := decMode.Unmarshal(v, &kidStr); err2 != nil {
				return Protected{}, fmt.Errorf("decode kid: %w", err)
			}
			p.Kid = kidStr
		} else {
			p.Kid = string(kidBytes)
		}
	}

	if v, ok := raw[HeaderTyp]; ok {
		var typ string
		if err := decMode.Unmarshal(v, &typ); err != nil {
			return Protected{}, fmt.Errorf("decode typ: %w", err)
		}
		p.Typ = typ
	}

	// RFC 9052 §3.1: if crit (label 2) is present, every listed label must
	// be present in the protected bucket AND processed by this implementation.
	// An empty or malformed crit is a fatal error.
	if v, ok := raw[HeaderCrit]; ok {
		if err := validateCrit(v, raw); err != nil {
			return Protected{}, err
		}
	}

	return p, nil
}

// processedLabels is the set of protected-header labels this implementation
// processes. Used by validateCrit to enforce RFC 9052 §3.1.
var processedLabels = map[int]bool{
	HeaderAlg:         true,
	HeaderCrit:        true,
	HeaderContentType: true,
	HeaderKid:         true,
	HeaderTyp:         true,
}

// validateCrit enforces RFC 9052 §3.1 for the crit parameter: the value must
// be a non-empty array of integers; every listed label must be present in the
// protected bucket and processed by this implementation.
func validateCrit(critRaw cbor.RawMessage, protMap map[int]cbor.RawMessage) error {
	var labels []int
	if err := decMode.Unmarshal(critRaw, &labels); err != nil {
		return fmt.Errorf("crit (label 2): must be an array of integers: %w", err)
	}
	if len(labels) == 0 {
		return fmt.Errorf("crit (label 2): empty array is not valid (RFC 9052 §3.1)")
	}
	for _, label := range labels {
		if !processedLabels[label] {
			return fmt.Errorf("crit (label 2): label %d is not processed by this implementation", label)
		}
		if _, present := protMap[label]; !present {
			return fmt.Errorf("crit (label 2): label %d is listed but not present in the protected header", label)
		}
	}
	return nil
}

// SignFunc signs a SHA-256 digest and returns the raw signature (64-byte r||s).
type SignFunc func(digest []byte) ([]byte, error)

// COSE_Sign1 is the CBOR structure: Tag(18, [protected, unprotected, payload, signature]).
// cborSign1 is the untagged array inside the tag.
type cborSign1 struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected map[interface{}]interface{}
	Payload     []byte
	Signature   []byte
}

// Sign1 builds a COSE_Sign1 message: CBOR tag 18 wrapping
// [protectedBytes, {}, payload, signature].
//
// The signing follows RFC 9052 §4.4: Sig_structure = ["Signature1",
// protectedBytes, externalAAD, payload], then SHA-256 of the CBOR-encoded
// Sig_structure, then ECDSA sign the digest.
func Sign1(prot Protected, payload []byte, sign SignFunc) ([]byte, error) {
	protBytes, err := prot.encode()
	if err != nil {
		return nil, fmt.Errorf("encode protected header: %w", err)
	}

	sigStructure, err := buildSigStructure(protBytes, payload)
	if err != nil {
		return nil, fmt.Errorf("build Sig_structure: %w", err)
	}

	digest := sha256.Sum256(sigStructure)

	sig, err := sign(digest[:])
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	// Trim the go-ethereum recovery byte if present.
	if len(sig) == 65 {
		sig = sig[:64]
	}
	if len(sig) != 64 {
		return nil, fmt.Errorf("signature must be 64 bytes (r||s), got %d", len(sig))
	}

	msg := cbor.Tag{
		Number:  18,
		Content: cborSign1{Protected: protBytes, Unprotected: map[interface{}]interface{}{}, Payload: payload, Signature: sig},
	}
	return encMode.Marshal(msg)
}

// Verify1 parses and verifies a COSE_Sign1 message, returning the protected
// header and payload on success.
func Verify1(data []byte, key *ecdsa.PublicKey, allowedAlgs []int) (Protected, []byte, error) {
	prot, payload, sig, err := Parse1(data)
	if err != nil {
		return Protected{}, nil, err
	}

	// Check the algorithm is one the caller allows.
	allowed := false
	for _, a := range allowedAlgs {
		if prot.Alg == a {
			allowed = true
			break
		}
	}
	if !allowed {
		return Protected{}, nil, fmt.Errorf("COSE alg %d is not in the allowed set %v", prot.Alg, allowedAlgs)
	}

	// Get the raw protected bytes and payload for the Sig_structure.
	raw, rerr := parseRaw(data)
	if rerr != nil {
		return Protected{}, nil, rerr
	}

	sigStructure, err := buildSigStructure(raw.Protected, raw.Payload)
	if err != nil {
		return Protected{}, nil, fmt.Errorf("build Sig_structure: %w", err)
	}

	digest := sha256.Sum256(sigStructure)

	if err := verifyECDSA(key, digest[:], sig, prot.Alg); err != nil {
		return Protected{}, nil, err
	}

	return prot, payload, nil
}

// Parse1 parses a COSE_Sign1 message without verifying the signature.
// Returns the protected header, payload, and raw signature.
func Parse1(data []byte) (Protected, []byte, []byte, error) {
	raw, err := parseRaw(data)
	if err != nil {
		return Protected{}, nil, nil, err
	}

	prot, err := decodeProtected(raw.Protected)
	if err != nil {
		return Protected{}, nil, nil, err
	}

	return prot, raw.Payload, raw.Signature, nil
}

// parseRaw extracts the raw COSE_Sign1 fields from CBOR bytes.
func parseRaw(data []byte) (cborSign1, error) {
	if len(data) == 0 {
		return cborSign1{}, fmt.Errorf("empty COSE_Sign1 input")
	}

	// Decode the outer structure. The cbor library may decode the tag content
	// as either cbor.RawMessage or []interface{} depending on the dec mode.
	// We use a two-step approach: first strip the tag, then decode the array.
	var tagged cbor.Tag
	if err := decMode.Unmarshal(data, &tagged); err != nil {
		return cborSign1{}, fmt.Errorf("decode COSE_Sign1 tag: %w", err)
	}
	if tagged.Number != 18 {
		return cborSign1{}, fmt.Errorf("expected CBOR tag 18 (COSE_Sign1), got %d", tagged.Number)
	}

	// The tag content is the CBOR-encoded 4-element array. Try RawMessage first,
	// then fall back to re-encoding if the library decoded it eagerly.
	var raw cborSign1
	switch content := tagged.Content.(type) {
	case cbor.RawMessage:
		if err := decMode.Unmarshal(content, &raw); err != nil {
			return cborSign1{}, fmt.Errorf("decode COSE_Sign1 array: %w", err)
		}
	default:
		// Re-encode the content to CBOR, then decode as the struct.
		reEncoded, err := encMode.Marshal(content)
		if err != nil {
			return cborSign1{}, fmt.Errorf("re-encode COSE_Sign1 content: %w", err)
		}
		if err := decMode.Unmarshal(reEncoded, &raw); err != nil {
			return cborSign1{}, fmt.Errorf("decode COSE_Sign1 array from re-encoded: %w", err)
		}
	}

	return raw, nil
}

// IsCOSESign1 reports whether data looks like a COSE_Sign1 message: it starts
// with CBOR tag 18 (0xd2) followed by a 4-element array.
func IsCOSESign1(data []byte) bool {
	if len(data) < 2 {
		return false
	}
	// CBOR tag 18: single-byte tag encoding is 0xc0 + 18 = 0xd2.
	// A 4-element array: 0x84.
	return data[0] == 0xd2 && data[1] == 0x84
}

// buildSigStructure builds the Sig_structure1 per RFC 9052 §4.4:
// Sig_structure1 = ["Signature1", protectedBytes, externalAAD, payload]
// externalAAD is empty (no external additional authenticated data).
func buildSigStructure(protectedBytes, payload []byte) ([]byte, error) {
	sigStructure := []interface{}{
		"Signature1",
		protectedBytes,
		[]byte{}, // external_aad
		payload,
	}
	return encMode.Marshal(sigStructure)
}

// verifyECDSA verifies a 64-byte r||s ECDSA signature over a SHA-256 digest.
func verifyECDSA(key *ecdsa.PublicKey, digest, sig []byte, alg int) error {
	if key == nil {
		return fmt.Errorf("public key is nil")
	}
	if len(sig) != 64 {
		return fmt.Errorf("COSE signature must be 64 bytes (r||s), got %d", len(sig))
	}

	// Check the algorithm matches the key's curve.
	switch alg {
	case AlgES256:
		if key.Curve != elliptic.P256() {
			return fmt.Errorf("alg ES256 (-7) requires a P-256 key, got %s", key.Curve.Params().Name)
		}
	case AlgES256K:
		// RFC 8812 §3.2: ES256K needs key type EC2 and curve secp256k1;
		// secp256k1 MUST be used only with ES256K. Exact curve comparison
		// against the go-ethereum singleton avoids accepting any other
		// 256-bit curve that just happens not to be P-256.
		if key.Curve != ethcrypto.S256() {
			return fmt.Errorf("alg ES256K (-47) requires a secp256k1 key")
		}
	default:
		return fmt.Errorf("unsupported COSE algorithm: %d", alg)
	}

	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])

	if !ecdsa.Verify(key, digest, r, s) {
		return fmt.Errorf("COSE_Sign1 signature verification failed")
	}
	return nil
}

// COSEAlgForJOSE maps a JOSE algorithm name to its COSE algorithm identifier.
func COSEAlgForJOSE(jose string) (int, error) {
	switch jose {
	case "ES256":
		return AlgES256, nil
	case "ES256K":
		return AlgES256K, nil
	}
	return 0, fmt.Errorf("unsupported JOSE algorithm for COSE: %s", jose)
}

// JOSEAlgForCOSE maps a COSE algorithm identifier to its JOSE algorithm name.
func JOSEAlgForCOSE(cose int) (string, error) {
	switch cose {
	case AlgES256:
		return "ES256", nil
	case AlgES256K:
		return "ES256K", nil
	}
	return "", fmt.Errorf("unsupported COSE algorithm: %d", cose)
}

// CBOR encoding/decoding modes. Deterministic encoding for the protected
// header and Sig_structure ensures Hash() is stable across serialisations.
var (
	encMode cbor.EncMode
	decMode cbor.DecMode
)

func init() {
	var err error
	encMode, err = cbor.EncOptions{
		Sort:          cbor.SortCanonical,
		IndefLength:   cbor.IndefLengthForbidden,
		TagsMd:        cbor.TagsAllowed,
		BigIntConvert: cbor.BigIntConvertNone,
	}.EncMode()
	if err != nil {
		panic(fmt.Sprintf("cose: init enc mode: %v", err))
	}

	decMode, err = cbor.DecOptions{
		TagsMd:    cbor.TagsAllowed,
		DupMapKey: cbor.DupMapKeyEnforcedAPF,
	}.DecMode()
	if err != nil {
		panic(fmt.Sprintf("cose: init dec mode: %v", err))
	}
}
