package sdjwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

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
