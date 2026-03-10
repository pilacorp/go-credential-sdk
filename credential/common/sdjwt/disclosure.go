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
	sdAlg, shuffle, err := validateAndGetDefaults(input)
	if err != nil {
		return nil, err
	}

	processedVC := util.DeepCopyMap(input.VC)

	// Process decoys even when there are no selective paths
	// Decoys require _sd_alg to be set
	if len(input.Decoys) > 0 {
		processedVC["_sd_alg"] = sdAlg
	}

	if len(input.SelectivePaths) == 0 && len(input.Decoys) == 0 {
		return &SDJWTResult{ProcessedVC: processedVC}, nil
	}

	if len(input.SelectivePaths) > 0 {
		processedVC["_sd_alg"] = sdAlg
	}

	disclosures, err := processSelectivePaths(processedVC, input.SelectivePaths, sdAlg)
	if err != nil {
		return nil, err
	}

	if err := processDecoys(processedVC, input.Decoys, sdAlg); err != nil {
		return nil, err
	}

	if shuffle {
		shuffleSDArrays(processedVC)
	}

	return &SDJWTResult{
		ProcessedVC: processedVC,
		Disclosures: disclosures,
	}, nil
}

// validateAndGetDefaults validates input and returns configured hash algorithm and shuffle flag.
func validateAndGetDefaults(input BuildDisclosuresInput) (string, bool, error) {
	sdAlg := DefaultHashAlgorithm
	if input.HashAlgorithm != "" {
		sdAlg = input.HashAlgorithm
	}

	if !supportedHashAlgorithms[sdAlg] {
		return "", false, fmt.Errorf("unsupported hash algorithm %q", sdAlg)
	}

	return sdAlg, input.Shuffle, nil
}

// processSelectivePaths processes all selective disclosure paths and returns disclosure strings.
func processSelectivePaths(vc map[string]interface{}, paths []string, sdAlg string) ([]string, error) {
	var disclosures []string

	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" {
			return nil, fmt.Errorf("empty path")
		}

		encodedDisclosure, err := processSinglePath(vc, path, sdAlg)
		if err != nil {
			return nil, err
		}

		disclosures = append(disclosures, encodedDisclosure)
	}

	return disclosures, nil
}

// processSinglePath processes a single selective disclosure path.
func processSinglePath(vc map[string]interface{}, path, sdAlg string) (string, error) {
	resolved, err := resolvePath(vc, path)
	if err != nil {
		return "", fmt.Errorf("resolve path %q: %w", path, err)
	}
	if resolved == nil {
		return "", fmt.Errorf("path %q not found", path)
	}

	encodedDisclosure, err := buildAndApplyDisclosure(resolved, path, sdAlg)
	if err != nil {
		return "", err
	}

	return encodedDisclosure, nil
}

// buildAndApplyDisclosure builds disclosure array, encodes it, hashes it, and applies to VC.
func buildAndApplyDisclosure(resolved *resolvedTarget, path, sdAlg string) (string, error) {
	salt, err := randomSalt()
	if err != nil {
		return "", fmt.Errorf("failed to generate salt for path %q: %w", path, err)
	}

	disclosureArr := buildDisclosureArray(resolved, salt)

	disclosureJSON, err := json.Marshal(disclosureArr)
	if err != nil {
		return "", fmt.Errorf("failed to marshal disclosure for path %q: %w", path, err)
	}

	encodedDisclosure := base64.RawURLEncoding.EncodeToString(disclosureJSON)

	h, err := hashDisclosure(sdAlg, encodedDisclosure)
	if err != nil {
		return "", fmt.Errorf("failed to hash disclosure for path %q: %w", path, err)
	}

	if err := applyDisclosureToVC(resolved, h); err != nil {
		return "", err
	}

	return encodedDisclosure, nil
}

// buildDisclosureArray builds the disclosure array based on the resolved target kind.
func buildDisclosureArray(resolved *resolvedTarget, salt string) []interface{} {
	switch resolved.kind {
	case TargetKindObjectField, TargetKindArrayContainer:
		return []interface{}{salt, resolved.fieldName, resolved.value}
	case TargetKindArrayElem:
		return []interface{}{salt, resolved.value}
	default:
		return nil
	}
}

// applyDisclosureToVC applies the disclosure digest to the VC structure.
func applyDisclosureToVC(resolved *resolvedTarget, digest string) error {
	switch resolved.kind {
	case TargetKindObjectField, TargetKindArrayContainer:
		m, ok := resolved.parent.(map[string]interface{})
		if !ok {
			return fmt.Errorf("parent is not a map")
		}
		appendSD(m, digest)
		delete(m, resolved.fieldName)
	case TargetKindArrayElem:
		arr, ok := resolved.parent.([]interface{})
		if !ok {
			return fmt.Errorf("parent is not an array")
		}
		arr[resolved.index] = map[string]interface{}{"...": digest}
	default:
		return fmt.Errorf("unexpected kind %q", resolved.kind)
	}
	return nil
}

// processDecoys processes all decoy configurations and adds decoy digests to the VC.
func processDecoys(vc map[string]interface{}, decoys []DecoyConfig, sdAlg string) error {
	for _, decoy := range decoys {
		if decoy.Count <= 0 {
			continue
		}

		hashes, err := generateDecoyHashes(sdAlg, decoy.Count)
		if err != nil {
			return fmt.Errorf("failed to generate decoy hashes for path %q: %w", decoy.Path, err)
		}

		if err := applyDecoyToVC(vc, decoy.Path, hashes); err != nil {
			return err
		}
	}
	return nil
}

// applyDecoyToVC applies decoy hashes to the VC at the specified path.
func applyDecoyToVC(vc map[string]interface{}, path string, hashes []string) error {
	resolved, err := resolvePath(vc, path)
	if err != nil {
		return fmt.Errorf("resolve decoy path %q: %w", path, err)
	}
	if resolved == nil {
		return nil
	}

	switch resolved.kind {
	case TargetKindObjectField:
		return applyDecoyToObjectField(resolved, hashes)
	case TargetKindArrayContainer:
		return applyDecoyToArrayContainer(resolved, hashes)
	case TargetKindArrayElem:
		return applyDecoyToArrayElement(resolved, hashes)
	}

	return nil
}

// applyDecoyToObjectField adds decoy hashes to an object's _sd array.
func applyDecoyToObjectField(resolved *resolvedTarget, hashes []string) error {
	var target map[string]interface{}
	var ok bool

	if resolved.value != nil {
		target, ok = resolved.value.(map[string]interface{})
		if !ok {
			return fmt.Errorf("decoy target value is not an object, got %T", resolved.value)
		}
	} else {
		target, ok = resolved.parent.(map[string]interface{})
		if !ok {
			return fmt.Errorf("decoy target parent is not an object, got %T", resolved.parent)
		}
	}

	for _, h := range hashes {
		appendSD(target, h)
	}
	return nil
}

// applyDecoyToArrayContainer adds new decoy elements to an array.
func applyDecoyToArrayContainer(resolved *resolvedTarget, hashes []string) error {
	arr, ok := resolved.value.([]interface{})
	if !ok {
		return fmt.Errorf("decoy target value is not an array, got %T", resolved.value)
	}

	parentMap, ok := resolved.parent.(map[string]interface{})
	if !ok {
		return fmt.Errorf("decoy target parent is not an object, got %T", resolved.parent)
	}

	// Create new array with decoys to avoid slice aliasing issues
	newArr := make([]interface{}, len(arr), len(arr)+len(hashes))
	copy(newArr, arr)
	for _, h := range hashes {
		decoyElem := map[string]interface{}{"...": h}
		newArr = append(newArr, decoyElem)
	}

	parentMap[resolved.fieldName] = newArr

	return nil
}

// applyDecoyToArrayElement appends decoy hashes at the end of the array.
// This modifies the slice in place using index-based access to ensure changes persist.
func applyDecoyToArrayElement(resolved *resolvedTarget, hashes []string) error {
	if len(hashes) == 0 {
		return nil
	}

	arr, ok := resolved.parent.([]interface{})
	if !ok {
		return fmt.Errorf("decoy target parent is not an array, got %T", resolved.parent)
	}

	// Append decoy placeholders using direct slice access
	// This modifies the underlying array in place
	for _, h := range hashes {
		arr = append(arr, map[string]interface{}{"...": h})
	}

	// Update resolved.parent to point to the modified slice
	// The underlying array has been modified in place
	resolved.parent = arr

	// Write back to parent map if we have parentMap and parentKey
	if resolved.parentMap != nil && resolved.parentKey != "" {
		(*resolved.parentMap)[resolved.parentKey] = arr
	}

	return nil
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
		return &resolvedTarget{parent: root, kind: TargetKindObjectField}, nil
	}

	segs, err := parsePath(path)
	if err != nil {
		return nil, err
	}
	if len(segs) == 0 {
		return &resolvedTarget{parent: root, kind: TargetKindObjectField}, nil
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
					return &resolvedTarget{parent: m, kind: TargetKindArrayContainer, fieldName: seg.key, value: arr}, nil
				}
				return &resolvedTarget{parent: m, kind: TargetKindObjectField, fieldName: seg.key, value: val}, nil
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
			var parentMapPtr *map[string]interface{}
			parentKey := ""
			if seg.key != "" {
				m, ok := current.(map[string]interface{})
				if ok {
					parentMapPtr = &m
					parentKey = seg.key
				}
			}
			return &resolvedTarget{
				parent:    arr,
				parentMap: parentMapPtr,
				parentKey: parentKey,
				kind:      TargetKindArrayElem,
				index:     idx,
				value:     arr[idx],
			}, nil
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
