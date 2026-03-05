package sdjwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

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
			return nil, nil, fmt.Errorf("empty path")
		}

		target, kind, fieldName, index, value, err := resolveDisclosureTarget(processedVC, path)
		if err != nil {
			return nil, nil, fmt.Errorf("resolve path %q: %w", path, err)
		}
		if target == nil {
			// Path not found; skip silently.
			return nil, nil, fmt.Errorf("path %q not found", path)
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
			return nil, nil, fmt.Errorf("unexpected kind %q at path %q", kind, path)
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
				return nil, nil, fmt.Errorf("expected map for objectField at path %q", path)
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
				return nil, nil, fmt.Errorf("expected slice for arrayElem at path %q", path)
			}
			if index < 0 || index >= len(arr) {
				return nil, nil, fmt.Errorf("index out of range for path %q", path)
			}
			arr[index] = map[string]interface{}{"...": h}
		}

	}

	return processedVC, disclosures, nil
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
