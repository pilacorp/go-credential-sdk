package sdjwt

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Parsed represents a parsed SD-JWT at the string level.
type Parsed struct {
	Raw             string   // original SD-JWT input (trimmed)
	IssuerSignedJWT string   // issuer-signed JWT (before first '~')
	Disclosures     []string // disclosure strings between '~' (base64url(JSON array))
}

// IsSDJWT checks whether the input string looks like an SD-JWT.
// It only validates the format:
//   - contains at least one '~'
//   - the part before the first '~' is a JWT (header.payload[.signature])
func IsSDJWT(raw string) bool {
	if raw == "" {
		return false
	}

	s := strings.TrimSpace(strings.Trim(raw, "\""))
	if !strings.Contains(s, "~") {
		return false
	}

	parts := strings.SplitN(s, "~", 2)
	if len(parts) < 2 {
		return false
	}

	return isJWT(parts[0])
}

// Parse splits an SD-JWT into issuer-signed JWT and its disclosures.
// It assumes the input has already been validated by IsSDJWT.
func Parse(raw string) (*Parsed, error) {
	if !IsSDJWT(raw) {
		return nil, fmt.Errorf("invalid SD-JWT format")
	}

	s := strings.TrimSpace(strings.Trim(raw, "\""))
	parts := strings.Split(s, "~")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid SD-JWT: missing disclosures or terminator")
	}

	issuer := parts[0]
	var disclosures []string
	for i := 1; i < len(parts); i++ {
		seg := strings.TrimSpace(parts[i])
		if seg == "" {
			continue
		}
		// If this is the last segment and it looks like a JWT, treat it as KB-JWT and stop.
		if i == len(parts)-1 && isJWT(seg) {
			break
		}
		disclosures = append(disclosures, seg)
	}

	return &Parsed{
		Raw:             s,
		IssuerSignedJWT: issuer,
		Disclosures:     disclosures,
	}, nil
}

// BuildDisclosures is used at issuing time to construct SD-JWT structures.
// It takes a plain VC payload (vcMap) and a list of field paths (dot + [index]
// notation) that should be selectively disclosable, and returns:
//   - processedVC: vcMap with those fields replaced by SD-JWT digests
//   - disclosures: disclosure strings D1..Dn (base64url(JSON array))
//
// Supported path format examples:
//   - "firstname"
//   - "person.firstname"
//   - "person.address.city"
//   - "tags[0]"
//   - "person.children[0].name"
func BuildDisclosures(vcMap map[string]interface{}, selectivePaths []string) (processedVC map[string]interface{}, disclosures []string, err error) {
	// Shallow copy the root map to avoid mutating caller's data.
	processedVC = make(map[string]interface{}, len(vcMap)+2)
	for k, v := range vcMap {
		processedVC[k] = v
	}

	if len(selectivePaths) == 0 {
		return processedVC, nil, nil
	}

	const sdAlg = "sha-256"
	processedVC["_sd_alg"] = sdAlg

	for _, path := range selectivePaths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}

		target, kind, fieldName, index, value, err := resolveDisclosureTarget(processedVC, path)
		if err != nil {
			return nil, nil, fmt.Errorf("resolve path %q: %w", path, err)
		}
		if target == nil {
			// Path not found; skip silently.
			continue
		}

		// Create disclosure array:
		// - Object field: [salt, claim_name, claim_value]
		// - Array element: [salt, claim_value]
		salt, err := randomSalt()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate salt for path %q: %w", path, err)
		}

		var disclosureArr []interface{}
		switch kind {
		case "objectField":
			disclosureArr = []interface{}{salt, fieldName, value}
		case "arrayElem":
			disclosureArr = []interface{}{salt, value}
		default:
			// Should not happen.
			continue
		}

		disclosureJSON, err := json.Marshal(disclosureArr)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to marshal disclosure for path %q: %w", path, err)
		}

		D := base64.RawURLEncoding.EncodeToString(disclosureJSON)
		disclosures = append(disclosures, D)

		// Compute digest h = digest_b64u(sdAlg, D)
		h, err := hashDisclosure(sdAlg, D)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to hash disclosure for path %q: %w", path, err)
		}

		// Attach digest to nearest object parent (_sd) or array placeholder.
		switch kind {
		case "objectField":
			m, ok := target.(map[string]interface{})
			if !ok {
				return nil, nil, fmt.Errorf("internal error: expected map for objectField at path %q", path)
			}

			// Append h into this object's _sd list.
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
				return nil, nil, fmt.Errorf("unexpected _sd type %T at path %q", existing, path)
			}

			// Remove original claim; it will be re-inserted via disclosure on holder side.
			delete(m, fieldName)

		case "arrayElem":
			arr, ok := target.([]interface{})
			if !ok {
				return nil, nil, fmt.Errorf("internal error: expected slice for arrayElem at path %q", path)
			}
			if index < 0 || index >= len(arr) {
				return nil, nil, fmt.Errorf("index out of range for path %q", path)
			}
			arr[index] = map[string]interface{}{"...": h}
		}

	}

	return processedVC, disclosures, nil
}

// Reconstruct rebuilds the processed SD-JWT payload from a vcMap containing
// SD-JWT digests and the provided disclosures. It implements the "Processed
// SD-JWT Payload" reconstruction from sd_jwt.md.
func Reconstruct(vcMap map[string]interface{}, disclosures []string) (map[string]interface{}, error) {
	// Determine algorithm
	sdAlg := "sha-256"
	if v, ok := vcMap["_sd_alg"].(string); ok && v != "" {
		sdAlg = v
	}

	// Build hash -> disclosure mapping
	disclosureMap := make(map[string]disclosureInfo, len(disclosures))

	for _, D := range disclosures {
		if D == "" {
			continue
		}

		h, err := hashDisclosure(sdAlg, D)
		if err != nil {
			return nil, fmt.Errorf("failed to hash disclosure: %w", err)
		}

		decoded, err := base64.RawURLEncoding.DecodeString(D)
		if err != nil {
			return nil, fmt.Errorf("failed to decode disclosure: %w", err)
		}

		var arr []interface{}
		if err := json.Unmarshal(decoded, &arr); err != nil {
			return nil, fmt.Errorf("failed to unmarshal disclosure: %w", err)
		}

		info := disclosureInfo{
			raw:   D,
			array: arr,
		}

		switch len(arr) {
		case 3:
			// [salt, name, value]
			if name, ok := arr[1].(string); ok {
				info.objectField = name
				info.value = arr[2]
				info.isArrayElem = false
			}
		case 2:
			// [salt, value]
			info.value = arr[1]
			info.isArrayElem = true
		default:
			// Unsupported structure; keep but will likely be ignored.
		}

		disclosureMap[h] = info
	}

	// Work on a shallow copy of root
	rootCopy := make(map[string]interface{}, len(vcMap))
	for k, v := range vcMap {
		rootCopy[k] = v
	}

	processed, err := processNode(rootCopy, disclosureMap)
	if err != nil {
		return nil, err
	}

	result, ok := processed.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("processed payload is not an object")
	}

	// Remove top-level _sd_alg if present
	delete(result, "_sd_alg")

	return result, nil
}

// pathSegment represents one step in a dot/[index] path.
type pathSegment struct {
	key   string
	index *int
}

// resolveDisclosureTarget walks the processedVC according to the given path
// and returns:
//   - parent node where the disclosure should attach (map or []interface{})
//   - kind: "objectField" or "arrayElem"
//   - fieldName or index and the current value at that path
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

		// Object property (no index)
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

		// Segment with index
		idx := *seg.index

		if seg.key != "" {
			// map[field] is array
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

		// Pure index on current array
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

		// Look for [index] suffix
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

		// Wildcard '*' is not yet supported.
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

// disclosureInfo holds parsed disclosure metadata used during reconstruction.
type disclosureInfo struct {
	raw         string
	array       []interface{}
	objectField string
	value       interface{}
	isArrayElem bool
}

// processNode recursively processes objects/arrays, applying disclosures.
func processNode(node interface{}, disclosureMap map[string]disclosureInfo) (interface{}, error) {
	switch v := node.(type) {
	case map[string]interface{}:
		// Handle _sd on this object first
		if rawSd, ok := v["_sd"]; ok {
			switch sdList := rawSd.(type) {
			case []interface{}:
				for _, item := range sdList {
					h, ok := item.(string)
					if !ok {
						continue
					}
					info, ok := disclosureMap[h]
					if !ok {
						continue
					}
					// Only object-field disclosures here
					if info.isArrayElem || info.objectField == "" {
						continue
					}
					if _, exists := v[info.objectField]; exists {
						return nil, fmt.Errorf("duplicate field %q when reconstructing SD-JWT object", info.objectField)
					}

					processedVal, err := processNode(info.value, disclosureMap)
					if err != nil {
						return nil, err
					}
					v[info.objectField] = processedVal
				}
			case []string:
				for _, h := range sdList {
					info, ok := disclosureMap[h]
					if !ok {
						continue
					}
					if info.isArrayElem || info.objectField == "" {
						continue
					}
					if _, exists := v[info.objectField]; exists {
						return nil, fmt.Errorf("duplicate field %q when reconstructing SD-JWT object", info.objectField)
					}
					processedVal, err := processNode(info.value, disclosureMap)
					if err != nil {
						return nil, err
					}
					v[info.objectField] = processedVal
				}
			}
			// Remove _sd after expansion
			delete(v, "_sd")
		}

		// Recurse into other fields
		for key, val := range v {
			processedChild, err := processNode(val, disclosureMap)
			if err != nil {
				return nil, err
			}
			v[key] = processedChild
		}
		return v, nil

	case []interface{}:
		var out []interface{}
		for _, elem := range v {
			// Check for placeholder { "...": h }
			if m, ok := elem.(map[string]interface{}); ok && len(m) == 1 {
				if rawHash, ok := m["..."]; ok {
					if h, ok := rawHash.(string); ok {
						info, exists := disclosureMap[h]
						if !exists {
							// Placeholder without disclosure is dropped
							continue
						}
						// Array-element disclosure
						processedVal, err := processNode(info.value, disclosureMap)
						if err != nil {
							return nil, err
						}
						out = append(out, processedVal)
						continue
					}
				}
			}

			processedElem, err := processNode(elem, disclosureMap)
			if err != nil {
				return nil, err
			}
			out = append(out, processedElem)
		}
		return out, nil

	default:
		return node, nil
	}
}

// isJWT performs a simple regex check for JWT format: header.payload[.signature].
func isJWT(s string) bool {
	s = strings.TrimSpace(s)

	// Allow optional trailing dot for unsigned-but-3-part forms (header.payload.).
	s = strings.TrimSuffix(s, ".")

	// Allow 2 or 3 non-empty segments: header.payload[.signature].
	const re = `^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+(\.[A-Za-z0-9\-_]+)?$`
	match, _ := regexp.MatchString(re, s)
	return match
}

// hashDisclosure computes digest_b64u(sdAlg, D) where D is a base64url disclosure string.
func hashDisclosure(sdAlg, disclosure string) (string, error) {
	switch strings.ToLower(sdAlg) {
	case "sha-256", "sha256":
		sum := sha256.Sum256([]byte(disclosure))
		return base64.RawURLEncoding.EncodeToString(sum[:]), nil
	default:
		return "", fmt.Errorf("unsupported sd_alg %q", sdAlg)
	}
}

// randomSalt generates a random salt string (base64url-encoded).
func randomSalt() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf[:]), nil
}
