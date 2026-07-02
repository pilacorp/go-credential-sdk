package bbs

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/fxamacker/cbor/v2"
)

var (
	baseProofHeader    = []byte{0xd9, 0x5d, 0x02}
	derivedProofHeader = []byte{0xd9, 0x5d, 0x03}
)

var cborDet = func() cbor.EncMode {
	em, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	return em
}()

type baseProof struct {
	BBSSignature      []byte
	BBSHeader         []byte
	PublicKey         []byte
	HMACKey           []byte
	MandatoryPointers []string
}

type disclosureData struct {
	bbsProof           []byte
	bbsSignature       []byte
	bbsHeader          []byte
	publicKey          []byte
	hmacKey            []byte
	labelMap           map[string]string // verifier c14n label -> issuer hmac label
	mandatoryIndexes   []int
	selectiveIndexes   []int
	revealedIndexes    []int
	presentationHeader []byte
	revealDoc          map[string]interface{}
}

func serializeBaseProofValue(p *baseProof) (string, error) {
	mandatoryPointers := p.MandatoryPointers
	if mandatoryPointers == nil {
		mandatoryPointers = []string{}
	}
	payload := []interface{}{p.BBSSignature, p.BBSHeader, p.PublicKey, p.HMACKey, mandatoryPointers}
	enc, err := cborDet.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("bbs: cbor marshal base proof: %w", err)
	}
	return multibaseProofValue(baseProofHeader, enc), nil
}

func parseBaseProofValue(proofValue string) (*baseProof, error) {
	raw, err := decodeProofValue(proofValue, baseProofHeader)
	if err != nil {
		return nil, err
	}
	var arr []cbor.RawMessage
	if err := cbor.Unmarshal(raw, &arr); err != nil {
		return nil, fmt.Errorf("bbs: cbor unmarshal base proof: %w", err)
	}
	if len(arr) != 5 {
		return nil, fmt.Errorf("bbs: base proof value: want 5 elements, got %d", len(arr))
	}
	out := &baseProof{}
	if err := cbor.Unmarshal(arr[0], &out.BBSSignature); err != nil {
		return nil, err
	}
	if err := cbor.Unmarshal(arr[1], &out.BBSHeader); err != nil {
		return nil, err
	}
	if err := cbor.Unmarshal(arr[2], &out.PublicKey); err != nil {
		return nil, err
	}
	if err := cbor.Unmarshal(arr[3], &out.HMACKey); err != nil {
		return nil, err
	}
	if err := cbor.Unmarshal(arr[4], &out.MandatoryPointers); err != nil {
		return nil, err
	}
	return out, nil
}

func serializeDerivedProofValue(d *disclosureData) (string, error) {
	compressed, err := compressLabelMap(d.labelMap)
	if err != nil {
		return "", err
	}
	mIdx := make([]uint64, len(d.mandatoryIndexes))
	for i, n := range d.mandatoryIndexes {
		mIdx[i] = uint64(n)
	}
	sIdx := make([]uint64, len(d.selectiveIndexes))
	for i, n := range d.selectiveIndexes {
		sIdx[i] = uint64(n)
	}
	rIdx := make([]uint64, len(d.revealedIndexes))
	for i, n := range d.revealedIndexes {
		rIdx[i] = uint64(n)
	}
	payload := []interface{}{d.bbsProof, compressed, mIdx, sIdx, rIdx, d.presentationHeader}
	enc, err := cborDet.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("bbs: cbor marshal derived proof: %w", err)
	}
	return multibaseProofValue(derivedProofHeader, enc), nil
}

func parseDerivedProofValue(proofValue string) (*disclosureData, error) {
	raw, err := decodeProofValue(proofValue, derivedProofHeader)
	if err != nil {
		return nil, err
	}
	var arr []cbor.RawMessage
	if err := cbor.Unmarshal(raw, &arr); err != nil {
		return nil, fmt.Errorf("bbs: cbor unmarshal derived proof: %w", err)
	}
	if len(arr) != 5 && len(arr) != 6 {
		return nil, fmt.Errorf("bbs: derived proof value: want 5 or 6 elements, got %d", len(arr))
	}
	out := &disclosureData{}
	if err := cbor.Unmarshal(arr[0], &out.bbsProof); err != nil {
		return nil, err
	}
	var compressed map[uint64]uint64
	if err := cbor.Unmarshal(arr[1], &compressed); err != nil {
		return nil, err
	}
	out.labelMap = decompressLabelMap(compressed)
	var mIdx []uint64
	if err := cbor.Unmarshal(arr[2], &mIdx); err != nil {
		return nil, err
	}
	out.mandatoryIndexes = make([]int, len(mIdx))
	for i, n := range mIdx {
		out.mandatoryIndexes[i] = int(n)
	}
	var sIdx []uint64
	if err := cbor.Unmarshal(arr[3], &sIdx); err != nil {
		return nil, err
	}
	out.selectiveIndexes = make([]int, len(sIdx))
	for i, n := range sIdx {
		out.selectiveIndexes[i] = int(n)
	}

	presentationIdx := 4
	if len(arr) == 6 {
		var rIdx []uint64
		if err := cbor.Unmarshal(arr[4], &rIdx); err != nil {
			return nil, err
		}
		out.revealedIndexes = make([]int, len(rIdx))
		for i, n := range rIdx {
			out.revealedIndexes[i] = int(n)
		}
		presentationIdx = 5
	}
	if err := cbor.Unmarshal(arr[presentationIdx], &out.presentationHeader); err != nil {
		return nil, err
	}
	return out, nil
}

func compressLabelMap(labelMap map[string]string) (map[uint64]uint64, error) {
	out := make(map[uint64]uint64, len(labelMap))
	for k, v := range labelMap {
		key, err := strconv.ParseUint(strings.TrimPrefix(k, "c14n"), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("bbs: label map key %q: %w", k, err)
		}
		val, err := strconv.ParseUint(strings.TrimPrefix(v, "b"), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("bbs: label map value %q: %w", v, err)
		}
		out[key] = val
	}
	return out, nil
}

func decompressLabelMap(compressed map[uint64]uint64) map[string]string {
	out := make(map[string]string, len(compressed))
	keys := make([]uint64, 0, len(compressed))
	for k := range compressed {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	for _, k := range keys {
		out[fmt.Sprintf("c14n%d", k)] = fmt.Sprintf("b%d", compressed[k])
	}
	return out
}

func multibaseProofValue(header, payload []byte) string {
	buf := append(append([]byte{}, header...), payload...)
	return "u" + base64.RawURLEncoding.EncodeToString(buf)
}

func decodeProofValue(proofValue string, header []byte) ([]byte, error) {
	if len(proofValue) == 0 || proofValue[0] != 'u' {
		return nil, fmt.Errorf("bbs: proof value must be base64url-no-pad multibase ('u')")
	}
	raw, err := base64.RawURLEncoding.DecodeString(proofValue[1:])
	if err != nil {
		return nil, fmt.Errorf("bbs: decode proof value: %w", err)
	}
	if !bytes.HasPrefix(raw, header) {
		return nil, fmt.Errorf("bbs: proof value has wrong header")
	}
	return raw[len(header):], nil
}
