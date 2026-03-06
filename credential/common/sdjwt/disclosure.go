package sdjwt

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"strings"
)

// SupportedHashAlgorithms defines the allowed hash algorithms for SD-JWT.
var SupportedHashAlgorithms = map[string]bool{
	"sha-256": true,
	"sha-384": true,
	"sha-512": true,
}

// DefaultHashAlgorithm is the default hash algorithm used when not specified.
const DefaultHashAlgorithm = "sha-256"

// DisclosureInfo contains metadata about a disclosure, useful for Holders
// to understand which disclosure corresponds to which field.
type DisclosureInfo struct {
	Disclosure string      // The disclosure string (base64url)
	Path       string      // The path to the field (e.g., "person.name", "tags[0]")
	FieldName  string      // The field name (for object fields)
	Index      *int        // The array index (for array elements)
	Value      interface{} // The original value (for reference)
	ArrayPath  string      // Full array path if in array context
	Digest     string      // The digest of this disclosure
}

// SDJWTResult contains the result of BuildDisclosures, including metadata for Holders.
type SDJWTResult struct {
	ProcessedVC     map[string]interface{} // VC with fields replaced by digests
	Disclosures     []string               // Disclosure strings
	DisclosureInfos []DisclosureInfo       // Metadata about each disclosure (in order)
	SDAlg           string                 // Hash algorithm used
}

// BuildDisclosures is used at issuing time to construct SD-JWT structures.
// It takes a plain VC payload (vcMap) and a list of field paths (dot + [index]
// notation) that should be selectively disclosable.
//
// Parameters:
//   - sdAlg: hash algorithm (sha-256, sha-384, sha-512). Empty string defaults to sha-256.
//   - shuffle: if true, shuffle _sd arrays to prevent disclosure order leakage.
//   - decoyPaths: parent paths where decoy digests should be added (e.g. "", "credentialSubject").
//   - decoyCounts: number of decoy digests per corresponding path (len must match decoyPaths).
//
// Supported path format examples:
//   - "firstname"
//   - "person.firstname"
//   - "person.address.city"
//   - "tags[0]"
//   - "person.children[0].name"
func BuildDisclosures(vcMap map[string]interface{}, selectivePaths []string, sdAlg string, shuffle bool, decoyPaths []string, decoyCounts []int) (*SDJWTResult, error) {
	if sdAlg == "" {
		sdAlg = DefaultHashAlgorithm
	}
	if !SupportedHashAlgorithms[sdAlg] {
		return nil, fmt.Errorf("unsupported hash algorithm %q", sdAlg)
	}

	// Deep copy to avoid mutating caller's data.
	raw, err := json.Marshal(vcMap)
	if err != nil {
		return nil, fmt.Errorf("failed to deep copy vcMap: %w", err)
	}
	var processedVC map[string]interface{}
	if err := json.Unmarshal(raw, &processedVC); err != nil {
		return nil, fmt.Errorf("failed to deep copy vcMap: %w", err)
	}

	if len(selectivePaths) == 0 {
		return &SDJWTResult{
			ProcessedVC: processedVC,
			SDAlg:       sdAlg,
		}, nil
	}

	processedVC["_sd_alg"] = sdAlg

	// Track disclosure info for holder
	var disclosureInfos []DisclosureInfo

	for _, path := range selectivePaths {
		path = strings.TrimSpace(path)
		if path == "" {
			return nil, fmt.Errorf("empty path")
		}

		target, kind, fieldName, index, value, err := resolveDisclosureTarget(processedVC, path)
		if err != nil {
			return nil, fmt.Errorf("resolve path %q: %w", path, err)
		}
		if target == nil {
			return nil, fmt.Errorf("path %q not found", path)
		}

		// Create disclosure array
		salt, err := randomSalt()
		if err != nil {
			return nil, fmt.Errorf("failed to generate salt for path %q: %w", path, err)
		}

		var disclosureArr []interface{}
		var arrayPath string
		switch kind {
		case "objectField":
			disclosureArr = []interface{}{salt, fieldName, value}
		case "arrayElem":
			disclosureArr = []interface{}{salt, value}
			arrayPath = path
		default:
			return nil, fmt.Errorf("unexpected kind %q at path %q", kind, path)
		}

		disclosureJSON, err := json.Marshal(disclosureArr)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal disclosure for path %q: %w", path, err)
		}

		D := base64.RawURLEncoding.EncodeToString(disclosureJSON)

		// Compute digest
		h, err := hashDisclosure(sdAlg, D)
		if err != nil {
			return nil, fmt.Errorf("failed to hash disclosure for path %q: %w", path, err)
		}

		// Track disclosure info
		disclosureInfos = append(disclosureInfos, DisclosureInfo{
			Disclosure: D,
			Path:       path,
			FieldName:  fieldName,
			Index:      &index,
			Value:      value,
			ArrayPath:  arrayPath,
			Digest:     h,
		})

		// Attach digest to parent
		switch kind {
		case "objectField":
			m, ok := target.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("expected map for objectField at path %q", path)
			}
			switch existing := m["_sd"].(type) {
			case nil:
				m["_sd"] = []interface{}{h}
			case []interface{}:
				m["_sd"] = append(existing, h)
			case []string:
				var arr []interface{}
				for _, s := range existing {
					arr = append(arr, s)
				}
				arr = append(arr, h)
				m["_sd"] = arr
			default:
				return nil, fmt.Errorf("unexpected _sd type %T at path %q", existing, path)
			}
			delete(m, fieldName)

		case "arrayElem":
			arr, ok := target.([]interface{})
			if !ok {
				return nil, fmt.Errorf("expected slice for arrayElem at path %q", path)
			}
			if index < 0 || index >= len(arr) {
				return nil, fmt.Errorf("index out of range for path %q", path)
			}
			arr[index] = map[string]interface{}{"...": h}
		}
	}

	// Shuffle _sd arrays if enabled
	if shuffle {
		shuffleSDArrays(processedVC)
	}

	// Add decoy digests at specified paths.
	// Decoys are random hashes injected into _sd arrays with no corresponding
	// disclosure, so holders never see them and verifiers cannot distinguish
	// them from unrevealed real digests.
	if len(decoyPaths) > 0 && len(decoyCounts) == len(decoyPaths) {
		for i, path := range decoyPaths {
			count := decoyCounts[i]
			if count <= 0 {
				continue
			}
			hashes, err := generateDecoyHashes(sdAlg, count)
			if err != nil {
				return nil, fmt.Errorf("failed to generate decoy hashes for path %q: %w", path, err)
			}
			target := resolveObjectByPath(processedVC, path)
			if target == nil {
				continue
			}
			sd, ok := target["_sd"].([]interface{})
			if !ok {
				sd = []interface{}{}
			}
			for _, h := range hashes {
				sd = append(sd, h)
			}
			target["_sd"] = sd
		}
	}

	// Build disclosures array in same order as disclosureInfos
	disclosures := make([]string, len(disclosureInfos))
	for i, info := range disclosureInfos {
		disclosures[i] = info.Disclosure
	}

	return &SDJWTResult{
		ProcessedVC:     processedVC,
		Disclosures:     disclosures,
		DisclosureInfos: disclosureInfos,
		SDAlg:           sdAlg,
	}, nil
}

// shuffleSDArrays recursively shuffles all _sd arrays in the VC map.
func shuffleSDArrays(node interface{}) {
	switch v := node.(type) {
	case map[string]interface{}:
		if sd, ok := v["_sd"].([]interface{}); ok {
			shuffled := make([]interface{}, len(sd))
			copy(shuffled, sd)
			for i := len(shuffled) - 1; i > 0; i-- {
				j, _ := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
				shuffled[i], shuffled[j.Int64()] = shuffled[j.Int64()], shuffled[i]
			}
			v["_sd"] = shuffled
		}
		for _, val := range v {
			shuffleSDArrays(val)
		}
	case []interface{}:
		for _, elem := range v {
			shuffleSDArrays(elem)
		}
	}
}

// generateDecoyHashes generates random hash strings that look like real digests
// but have no corresponding disclosure.
func generateDecoyHashes(sdAlg string, count int) ([]string, error) {
	hashes := make([]string, count)
	for i := 0; i < count; i++ {
		salt, err := randomSalt()
		if err != nil {
			return nil, err
		}
		h, err := hashDisclosure(sdAlg, salt)
		if err != nil {
			return nil, err
		}
		hashes[i] = h
	}
	return hashes, nil
}

// resolveObjectByPath walks a dot-separated path and returns the map at that location.
// An empty path returns the root itself.
func resolveObjectByPath(root map[string]interface{}, path string) map[string]interface{} {
	if path == "" {
		return root
	}
	parts := strings.Split(path, ".")
	var current interface{} = root
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		m, ok := current.(map[string]interface{})
		if !ok {
			return nil
		}
		current, ok = m[part]
		if !ok {
			return nil
		}
	}
	if m, ok := current.(map[string]interface{}); ok {
		return m
	}
	return nil
}

// resolveDisclosureTarget walks the processedVC according to the given path
func resolveDisclosureTarget(root map[string]interface{}, path string) (parent interface{}, kind string, fieldName string, index int, value interface{}, err error) {
	segs, err := parsePath(path)
	if err != nil {
		return nil, "", "", 0, nil, err
	}
	if len(segs) == 0 {
		return nil, "", "", 0, nil, nil
	}

	var current interface{} = root

	for i, seg := range segs {
		last := i == len(segs)-1

		if seg.index == nil {
			m, ok := current.(map[string]interface{})
			if !ok {
				return nil, "", "", 0, nil, fmt.Errorf("segment %q expects object but got %T", seg.key, current)
			}
			if last {
				val, ok := m[seg.key]
				if !ok {
					return nil, "", "", 0, nil, nil
				}
				return m, "objectField", seg.key, 0, val, nil
			}

			next, ok := m[seg.key]
			if !ok {
				return nil, "", "", 0, nil, nil
			}
			current = next
			continue
		}

		idx := *seg.index

		if seg.key != "" {
			m, ok := current.(map[string]interface{})
			if !ok {
				return nil, "", "", 0, nil, fmt.Errorf("segment %q expects object but got %T", seg.key, current)
			}
			rawArr, ok := m[seg.key]
			if !ok {
				return nil, "", "", 0, nil, nil
			}
			arr, ok := rawArr.([]interface{})
			if !ok {
				return nil, "", "", 0, nil, fmt.Errorf("segment %q expects array but got %T", seg.key, rawArr)
			}
			if idx < 0 || idx >= len(arr) {
				return nil, "", "", 0, nil, nil
			}

			if last {
				return arr, "arrayElem", "", idx, arr[idx], nil
			}

			current = arr[idx]
			continue
		}

		arr, ok := current.([]interface{})
		if !ok {
			return nil, "", "", 0, nil, fmt.Errorf("segment [%d] expects array but got %T", idx, current)
		}
		if idx < 0 || idx >= len(arr) {
			return nil, "", "", 0, nil, nil
		}

		if last {
			return arr, "arrayElem", "", idx, arr[idx], nil
		}

		current = arr[idx]
	}

	return nil, "", "", 0, nil, nil
}

// parsePath parses a dot + [index] notation path into segments.
func parsePath(path string) ([]pathSegment, error) {
	if path == "" {
		return nil, nil
	}
	parts := strings.Split(path, ".")
	segs := make([]pathSegment, 0, len(parts))

	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}

		bracketIdx := strings.Index(p, "[")
		if bracketIdx == -1 {
			segs = append(segs, pathSegment{key: p})
			continue
		}

		key := p[:bracketIdx]
		rest := p[bracketIdx:]
		if !strings.HasPrefix(rest, "[") || !strings.HasSuffix(rest, "]") {
			return nil, fmt.Errorf("invalid array segment %q in path %q", p, path)
		}

		idxStr := rest[1 : len(rest)-1]
		if idxStr == "" {
			return nil, fmt.Errorf("empty index in path %q", path)
		}

		if idxStr == "*" {
			return nil, fmt.Errorf("wildcard index '*' is not supported in path %q", path)
		}

		i, err := strconv.Atoi(idxStr)
		if err != nil {
			return nil, fmt.Errorf("invalid index %q in path %q", idxStr, path)
		}

		seg := pathSegment{key: key, index: &i}
		segs = append(segs, seg)
	}

	return segs, nil
}
