package ecdsasd

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/fxamacker/cbor/v2"
)

// Spec-conformant ecdsa-sd-2023 proof value serialization (W3C vc-di-ecdsa).
// Base proof header 0xd95d00, derived proof header 0xd95d01, CBOR payload,
// then multibase base64url-no-pad with a leading 'u'.
var (
	baseProofHeader    = []byte{0xd9, 0x5d, 0x00}
	derivedProofHeader = []byte{0xd9, 0x5d, 0x01}
)

// cborDet encodes with RFC 8949 core-deterministic rules (sorted map keys,
// shortest-form integers, definite lengths) so the proofValue is byte-exact and
// matches the reference cborg encoder.
var cborDet = func() cbor.EncMode {
	em, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	return em
}()

type specBaseProof struct {
	BaseSignature     []byte
	PublicKey         []byte // 35-byte Multikey-encoded ephemeral public key
	HMACKey           []byte
	Signatures        [][]byte
	MandatoryPointers []string
}

type specDerivedProof struct {
	BaseSignature    []byte
	PublicKey        []byte
	Signatures       [][]byte
	LabelMap         map[string]string // "c14nN" -> "u<base64url>"
	MandatoryIndexes []int
}

func serializeBaseProofValue(p *specBaseProof) (string, error) {
	// Encode mandatoryPointers as an empty CBOR array (not null) when none were
	// given, so the proof value always carries the array component per spec.
	mandatoryPointers := p.MandatoryPointers
	if mandatoryPointers == nil {
		mandatoryPointers = []string{}
	}
	payload := []interface{}{p.BaseSignature, p.PublicKey, p.HMACKey, p.Signatures, mandatoryPointers}
	enc, err := cborDet.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("ecdsasd: cbor marshal base proof: %w", err)
	}
	return multibaseProofValue(baseProofHeader, enc), nil
}

func parseBaseProofValue(proofValue string) (*specBaseProof, error) {
	raw, err := decodeProofValue(proofValue, baseProofHeader)
	if err != nil {
		return nil, err
	}
	var arr []cbor.RawMessage
	if err := cbor.Unmarshal(raw, &arr); err != nil {
		return nil, fmt.Errorf("ecdsasd: cbor unmarshal base proof: %w", err)
	}
	if len(arr) != 5 {
		return nil, fmt.Errorf("ecdsasd: base proof value: want 5 elements, got %d", len(arr))
	}
	out := &specBaseProof{}
	if err := cbor.Unmarshal(arr[0], &out.BaseSignature); err != nil {
		return nil, err
	}
	if err := cbor.Unmarshal(arr[1], &out.PublicKey); err != nil {
		return nil, err
	}
	if err := cbor.Unmarshal(arr[2], &out.HMACKey); err != nil {
		return nil, err
	}
	if err := cbor.Unmarshal(arr[3], &out.Signatures); err != nil {
		return nil, err
	}
	if err := cbor.Unmarshal(arr[4], &out.MandatoryPointers); err != nil {
		return nil, err
	}
	return out, nil
}

func serializeDisclosureProofValue(p *specDerivedProof) (string, error) {
	compressed, err := compressLabelMap(p.LabelMap)
	if err != nil {
		return "", err
	}
	mIdx := make([]uint64, len(p.MandatoryIndexes))
	for i, n := range p.MandatoryIndexes {
		mIdx[i] = uint64(n)
	}
	payload := []interface{}{p.BaseSignature, p.PublicKey, p.Signatures, compressed, mIdx}
	enc, err := cborDet.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("ecdsasd: cbor marshal derived proof: %w", err)
	}
	return multibaseProofValue(derivedProofHeader, enc), nil
}

func parseDisclosureProofValue(proofValue string) (*specDerivedProof, error) {
	raw, err := decodeProofValue(proofValue, derivedProofHeader)
	if err != nil {
		return nil, err
	}
	var arr []cbor.RawMessage
	if err := cbor.Unmarshal(raw, &arr); err != nil {
		return nil, fmt.Errorf("ecdsasd: cbor unmarshal derived proof: %w", err)
	}
	if len(arr) != 5 {
		return nil, fmt.Errorf("ecdsasd: derived proof value: want 5 elements, got %d", len(arr))
	}
	out := &specDerivedProof{}
	if err := cbor.Unmarshal(arr[0], &out.BaseSignature); err != nil {
		return nil, err
	}
	if err := cbor.Unmarshal(arr[1], &out.PublicKey); err != nil {
		return nil, err
	}
	if err := cbor.Unmarshal(arr[2], &out.Signatures); err != nil {
		return nil, err
	}
	var compressed map[uint64][]byte
	if err := cbor.Unmarshal(arr[3], &compressed); err != nil {
		return nil, err
	}
	out.LabelMap = decompressLabelMap(compressed)
	var mIdx []uint64
	if err := cbor.Unmarshal(arr[4], &mIdx); err != nil {
		return nil, err
	}
	out.MandatoryIndexes = make([]int, len(mIdx))
	for i, n := range mIdx {
		out.MandatoryIndexes[i] = int(n)
	}
	return out, nil
}

func compressLabelMap(labelMap map[string]string) (map[uint64][]byte, error) {
	out := make(map[uint64][]byte, len(labelMap))
	for k, v := range labelMap {
		num, err := strconv.ParseUint(strings.TrimPrefix(k, "c14n"), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("ecdsasd: label map key %q: %w", k, err)
		}
		b, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(v, "u"))
		if err != nil {
			return nil, fmt.Errorf("ecdsasd: label map value %q: %w", v, err)
		}
		out[num] = b
	}
	return out, nil
}

func decompressLabelMap(compressed map[uint64][]byte) map[string]string {
	out := make(map[string]string, len(compressed))
	keys := make([]uint64, 0, len(compressed))
	for k := range compressed {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	for _, k := range keys {
		out[fmt.Sprintf("c14n%d", k)] = "u" + base64.RawURLEncoding.EncodeToString(compressed[k])
	}
	return out
}

func multibaseProofValue(header, payload []byte) string {
	buf := append(append([]byte{}, header...), payload...)
	return "u" + base64.RawURLEncoding.EncodeToString(buf)
}

func decodeProofValue(proofValue string, header []byte) ([]byte, error) {
	if len(proofValue) == 0 || proofValue[0] != 'u' {
		return nil, fmt.Errorf("ecdsasd: proof value must be base64url-no-pad multibase ('u')")
	}
	raw, err := base64.RawURLEncoding.DecodeString(proofValue[1:])
	if err != nil {
		return nil, fmt.Errorf("ecdsasd: decode proof value: %w", err)
	}
	if !bytes.HasPrefix(raw, header) {
		return nil, fmt.Errorf("ecdsasd: proof value has wrong header")
	}
	return raw[len(header):], nil
}
