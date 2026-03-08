package sdjwt

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/pilacorp/go-credential-sdk/credential/common/util"
)

const (
	AlgSHA256 = "sha-256"
	AlgSHA384 = "sha-384"
	AlgSHA512 = "sha-512"

	DefaultHashAlgorithm = AlgSHA256

	kindObjectField    = "objectField"
	kindArrayElem      = "arrayElem"
	kindArrayContainer = "arrayContainer"
)

// supportedHashAlgorithms defines the allowed hash algorithms for SD-JWT.
var supportedHashAlgorithms = map[string]bool{
	AlgSHA256: true,
	AlgSHA384: true,
	AlgSHA512: true,
}

// DecoyConfig specifies where and how many decoy digests to add.
type DecoyConfig struct {
	Path  string // parent path where decoy digests should be added (e.g. "", "credentialSubject").
	Count int    // number of decoy digests to add at this path.
}

// BuildDisclosuresInput is the input struct for BuildDisclosures.
type BuildDisclosuresInput struct {
	VC             map[string]interface{} // VC payload to process
	SelectivePaths []string               // field paths to make selectively disclosable
	HashAlgorithm  string                 // hash algorithm (sha-256, sha-384, sha-512). Empty defaults to sha-256.
	Shuffle        bool                   // if true, shuffle _sd arrays to prevent disclosure order leakage.
	Decoys         []DecoyConfig          // decoy digests to add at specific paths.
}

// SDJWTResult contains the result of BuildDisclosures.
// Holder-facing metadata is available via Parse() -> ParsedSDJWT.DecodedDisclosures.
type SDJWTResult struct {
	ProcessedVC map[string]interface{} // VC with fields replaced by digests
	Disclosures []string               // Disclosure strings (base64url)
}

// BuildDisclosures is used at issuing time to construct SD-JWT structures.
// It takes a plain VC payload (vcMap) and a list of field paths (dot + [index]
// notation) that should be selectively disclosable.
//
// Supported path format examples:
//   - "firstname"
//   - "person.firstname"
//   - "person.address.city"
//   - "tags[0]"
//   - "person.children[0].name"
func BuildDisclosures(input BuildDisclosuresInput) (*SDJWTResult, error) {
	// Apply defaults
	sdAlg := DefaultHashAlgorithm
	shuffle := input.Shuffle
	decoys := input.Decoys

	if input.HashAlgorithm != "" {
		sdAlg = input.HashAlgorithm
	}

	if !supportedHashAlgorithms[sdAlg] {
		return nil, fmt.Errorf("unsupported hash algorithm %q", sdAlg)
	}

	processedVC := util.DeepCopyMap(input.VC)

	if len(input.SelectivePaths) == 0 {
		return &SDJWTResult{
			ProcessedVC: processedVC,
		}, nil
	}

	processedVC["_sd_alg"] = sdAlg

	var disclosures []string

	for _, path := range input.SelectivePaths {
		path = strings.TrimSpace(path)
		if path == "" {
			return nil, fmt.Errorf("empty path")
		}

		resolved, err := resolvePath(processedVC, path)
		if err != nil {
			return nil, fmt.Errorf("resolve path %q: %w", path, err)
		}
		if resolved == nil {
			return nil, fmt.Errorf("path %q not found", path)
		}

		salt, err := randomSalt()
		if err != nil {
			return nil, fmt.Errorf("failed to generate salt for path %q: %w", path, err)
		}

		var disclosureArr []interface{}
		switch resolved.kind {
		case kindObjectField, kindArrayContainer:
			// Array container is treated same as object field
			disclosureArr = []interface{}{salt, resolved.fieldName, resolved.value}
		case kindArrayElem:
			disclosureArr = []interface{}{salt, resolved.value}
		default:
			return nil, fmt.Errorf("unexpected kind %q at path %q", resolved.kind, path)
		}

		disclosureJSON, err := json.Marshal(disclosureArr)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal disclosure for path %q: %w", path, err)
		}

		encodedDisclosure := base64.RawURLEncoding.EncodeToString(disclosureJSON)

		h, err := hashDisclosure(sdAlg, encodedDisclosure)
		if err != nil {
			return nil, fmt.Errorf("failed to hash disclosure for path %q: %w", path, err)
		}

		disclosures = append(disclosures, encodedDisclosure)

		switch resolved.kind {
		case kindObjectField, kindArrayContainer:
			// Array container is treated same as object field
			m, ok := resolved.parent.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("parent is not a map for path %q", path)
			}
			appendSD(m, h)
			delete(m, resolved.fieldName)
		case kindArrayElem:
			arr, ok := resolved.parent.([]interface{})
			if !ok {
				return nil, fmt.Errorf("parent is not an array for path %q", path)
			}
			arr[resolved.index] = map[string]interface{}{"...": h}
		}
	}

	// Add decoy digests at specified paths.
	// Decoys are random hashes injected into _sd arrays with no corresponding
	// disclosure, so holders never see them and verifiers cannot distinguish
	// them from unrevealed real digests.
	for _, decoy := range decoys {
		if decoy.Count <= 0 {
			continue
		}
		hashes, err := generateDecoyHashes(sdAlg, decoy.Count)
		if err != nil {
			return nil, fmt.Errorf("failed to generate decoy hashes for path %q: %w", decoy.Path, err)
		}
		// Use resolvePath - for decoys we need the parent (map for object, array for array)
		resolved, err := resolvePath(processedVC, decoy.Path)
		if err != nil {
			return nil, fmt.Errorf("resolve decoy path %q: %w", decoy.Path, err)
		}
		if resolved == nil {
			continue
		}
		// Handle object field decoys
		if resolved.kind == kindObjectField {
			// If value exists (path like "credentialSubject"), add to the value object
			// If value is nil (empty path ""), add to parent (root)
			var target map[string]interface{}
			var ok bool
			if resolved.value != nil {
				target, ok = resolved.value.(map[string]interface{})
				if !ok {
					continue
				}
			} else {
				target, ok = resolved.parent.(map[string]interface{})
				if !ok {
					continue
				}
			}
			for _, h := range hashes {
				appendSD(target, h)
			}
		}
		// Skip empty path - handled in array container case
		// Handle array container decoys: add new decoy elements to array
		if resolved.kind == kindArrayContainer {
			arr, ok := resolved.value.([]interface{})
			if !ok {
				continue
			}
			parentMap, ok := resolved.parent.(map[string]interface{})
			if !ok {
				continue
			}
			// Add decoy elements to the array
			for _, h := range hashes {
				decoyElem := map[string]interface{}{"...": h}
				arr = append(arr, decoyElem)
			}
			// Update the array in parent
			parentMap[resolved.fieldName] = arr
			continue
		}

		// Handle array element decoys (legacy - replaces element, may be deprecated)
		if resolved.kind == kindArrayElem {
			arr, ok := resolved.parent.([]interface{})
			if !ok {
				continue
			}
			idx := resolved.index
			if idx < 0 || idx >= len(arr) {
				continue
			}
			// Replace array element with decoy hash wrapped in "..." structure
			for _, h := range hashes {
				arr[idx] = map[string]interface{}{"...": h}
			}
		}
	}

	// Shuffle _sd arrays if enabled
	if shuffle {
		shuffleSDArrays(processedVC)
	}

	return &SDJWTResult{
		ProcessedVC: processedVC,
		Disclosures: disclosures,
	}, nil
}

// appendSD appends a digest to the _sd array of an object node.
func appendSD(m map[string]interface{}, digest string) {
	switch existing := m["_sd"].(type) {
	case nil:
		m["_sd"] = []interface{}{digest}
	case []interface{}:
		m["_sd"] = append(existing, digest)
	case []string:
		arr := make([]interface{}, len(existing), len(existing)+1)
		for i, s := range existing {
			arr[i] = s
		}
		m["_sd"] = append(arr, digest)
	}
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

// resolvePath walks a dot + [index] path and returns the resolved target with metadata.
// Used for both selective disclosures and decoy digests.
// An empty path returns the root itself.
// Returns (nil, nil) when the path does not exist in root.
func resolvePath(root map[string]interface{}, path string) (*resolvedTarget, error) {
	// Empty path returns root (for decoys at root level)
	if path == "" {
		return &resolvedTarget{parent: root, kind: kindObjectField}, nil
	}

	segs, err := parsePath(path)
	if err != nil {
		return nil, err
	}
	if len(segs) == 0 {
		return &resolvedTarget{parent: root, kind: kindObjectField}, nil
	}

	var current interface{} = root

	for i, seg := range segs {
		last := i == len(segs)-1

		if seg.index == nil {
			m, ok := current.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("segment %q expects object but got %T", seg.key, current)
			}
			val, ok := m[seg.key]
			if !ok {
				return nil, nil
			}
			if last {
				// Check if value is an array - if so, it's an array container
				if arr, isArr := val.([]interface{}); isArr {
					return &resolvedTarget{parent: m, kind: kindArrayContainer, fieldName: seg.key, value: arr}, nil
				}
				return &resolvedTarget{parent: m, kind: kindObjectField, fieldName: seg.key, value: val}, nil
			}
			current = val
			continue
		}

		arr, err := resolveArray(current, seg)
		if err != nil {
			return nil, err
		}
		if arr == nil {
			return nil, nil
		}

		idx := *seg.index
		if idx < 0 || idx >= len(arr) {
			return nil, fmt.Errorf("index %d out of range (len %d) for path %q", idx, len(arr), path)
		}
		if last {
			return &resolvedTarget{parent: arr, kind: kindArrayElem, index: idx, value: arr[idx]}, nil
		}
		current = arr[idx]
	}

	return nil, nil
}

// resolveArray extracts []interface{} from the current node for an indexed segment.
// If seg.key is set, it dereferences that key from the current object first.
func resolveArray(current interface{}, seg pathSegment) ([]interface{}, error) {
	if seg.key != "" {
		m, ok := current.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("segment %q expects object but got %T", seg.key, current)
		}
		raw, ok := m[seg.key]
		if !ok {
			return nil, nil
		}
		arr, ok := raw.([]interface{})
		if !ok {
			return nil, fmt.Errorf("segment %q expects array but got %T", seg.key, raw)
		}
		return arr, nil
	}

	arr, ok := current.([]interface{})
	if !ok {
		return nil, fmt.Errorf("segment [%d] expects array but got %T", *seg.index, current)
	}
	return arr, nil
}

// parsePath parses a dot + [index] notation path into segments.
func parsePath(path string) ([]pathSegment, error) {
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
		if !strings.HasSuffix(rest, "]") {
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
