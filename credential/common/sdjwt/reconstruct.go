package sdjwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/pilacorp/go-credential-sdk/credential/common/util"
)

// ValidationConfig holds configuration for SD-JWT validation.
type ValidationConfig struct {
	// RequireHashAlgorithmMatch if true, validates that _sd_alg matches the hash used
	RequireHashAlgorithmMatch bool
	// RejectDecoyDigests if true, rejects decoy digests (those starting with "_")
	RejectDecoyDigests bool
	// AllowUnreferencedDisclosures if false, rejects disclosures not referenced by any digest
	AllowUnreferencedDisclosures bool
}

// DefaultValidationConfig returns the default validation configuration.
func DefaultValidationConfig() *ValidationConfig {
	return &ValidationConfig{
		RequireHashAlgorithmMatch:    true,
		RejectDecoyDigests:           false,
		AllowUnreferencedDisclosures: false,
	}
}

// Reconstruct rebuilds the processed SD-JWT payload from a vcMap containing
// SD-JWT digests and the provided disclosures. It implements the "Processed
// SD-JWT Payload" reconstruction from sd_jwt.md.
//
// Validation is performed according to the provided ValidationConfig.
// If config is nil, DefaultValidationConfig() is used.
func Reconstruct(vcMap map[string]interface{}, disclosures []string, config *ValidationConfig) (map[string]interface{}, error) {
	if config == nil {
		config = DefaultValidationConfig()
	}

	// Determine algorithm
	sdAlg := DefaultHashAlgorithm
	if v, ok := vcMap["_sd_alg"].(string); ok && v != "" {
		sdAlg = v
	}

	// Validate hash algorithm is supported
	if !supportedHashAlgorithms[sdAlg] {
		return nil, fmt.Errorf("unsupported _sd_alg: %q", sdAlg)
	}

	// Build hash -> disclosure mapping
	disclosureMap := make(map[string]disclosureInfo, len(disclosures))

	// First pass: parse all disclosures and check for duplicate digests
	seenDigests := make(map[string]bool)

	for _, D := range disclosures {
		if D == "" {
			continue
		}

		h, err := hashDisclosure(sdAlg, D)
		if err != nil {
			return nil, fmt.Errorf("failed to hash disclosure: %w", err)
		}

		// Check for duplicate digests
		if seenDigests[h] {
			return nil, fmt.Errorf("duplicate digest found in disclosures")
		}
		seenDigests[h] = true

		decoded, err := base64.RawURLEncoding.DecodeString(D)
		if err != nil {
			return nil, fmt.Errorf("failed to decode disclosure %q: %w", D, err)
		}

		var arr []interface{}
		if err := json.Unmarshal(decoded, &arr); err != nil {
			return nil, fmt.Errorf("failed to unmarshal disclosure: %w", err)
		}

		// Validate disclosure structure
		if len(arr) != 2 && len(arr) != 3 {
			return nil, fmt.Errorf("invalid disclosure structure: expected 2 or 3 elements, got %d", len(arr))
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
			} else {
				return nil, fmt.Errorf("disclosure field name must be a string")
			}
		case 2:
			// [salt, value]
			info.value = arr[1]
			info.isArrayElem = true
		}

		disclosureMap[h] = info
	}

	rootCopy := util.DeepCopyMap(vcMap)

	// Track which disclosures are used during reconstruction
	usedDisclosures := make(map[string]bool)

	processed, err := processNode(rootCopy, disclosureMap, usedDisclosures, config)
	if err != nil {
		return nil, err
	}

	result, ok := processed.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("processed payload is not an object")
	}

	// Remove top-level _sd_alg if present
	delete(result, "_sd_alg")

	// Validate: check for unreferenced disclosures if required
	if !config.AllowUnreferencedDisclosures {
		for h, info := range disclosureMap {
			if !usedDisclosures[h] {
				// Check if this is a decoy digest
				if config.RejectDecoyDigests && info.objectField == "_decoy" {
					continue // Allow decoys if configured
				}
				return nil, fmt.Errorf("unreferenced disclosure found: field %q", info.objectField)
			}
		}
	}

	return result, nil
}

// processNode recursively processes objects/arrays, applying disclosures.
func processNode(node interface{}, disclosureMap map[string]disclosureInfo, usedDisclosures map[string]bool, config *ValidationConfig) (interface{}, error) {
	switch v := node.(type) {
	case map[string]interface{}:
		// Handle _sd on this object first
		if rawSd, ok := v["_sd"]; ok {
			// Track all digests in this object to check for duplicates
			objectDigests := make(map[string]bool)

			switch sdList := rawSd.(type) {
			case []interface{}:
				for _, item := range sdList {
					h, ok := item.(string)
					if !ok {
						continue
					}

					// Check for duplicate digest within this object
					if objectDigests[h] {
						return nil, fmt.Errorf("duplicate digest %q found in _sd array", h)
					}
					objectDigests[h] = true

					info, ok := disclosureMap[h]
					if !ok {
						// No disclosure for this digest - it's either unrevealed or a decoy
						continue
					}

					// Validate disclosure type matches context
					if info.isArrayElem || info.objectField == "" {
						return nil, fmt.Errorf("array element disclosure used in object context")
					}

					if _, exists := v[info.objectField]; exists {
						return nil, fmt.Errorf("duplicate field %q when reconstructing SD-JWT object", info.objectField)
					}

					// Track usage
					usedDisclosures[h] = true

					processedVal, err := processNode(info.value, disclosureMap, usedDisclosures, config)
					if err != nil {
						return nil, err
					}
					v[info.objectField] = processedVal
				}
			case []string:
				for _, h := range sdList {
					// Check for duplicate digest within this object
					if objectDigests[h] {
						return nil, fmt.Errorf("duplicate digest %q found in _sd array", h)
					}
					objectDigests[h] = true

					info, ok := disclosureMap[h]
					if !ok {
						continue
					}

					if info.isArrayElem || info.objectField == "" {
						return nil, fmt.Errorf("array element disclosure used in object context")
					}

					if _, exists := v[info.objectField]; exists {
						return nil, fmt.Errorf("duplicate field %q when reconstructing SD-JWT object", info.objectField)
					}

					usedDisclosures[h] = true

					processedVal, err := processNode(info.value, disclosureMap, usedDisclosures, config)
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
			processedChild, err := processNode(val, disclosureMap, usedDisclosures, config)
			if err != nil {
				return nil, err
			}
			v[key] = processedChild
		}
		return v, nil

	case []interface{}:
		var out []interface{}
		// Track all digests in this array to check for duplicates
		arrayDigests := make(map[string]bool)
		for _, elem := range v {
			// Check for placeholder { "...": h }
			if m, ok := elem.(map[string]interface{}); ok && len(m) == 1 {
				if rawHash, ok := m["..."]; ok {
					if h, ok := rawHash.(string); ok {
						if arrayDigests[h] {
							return nil, fmt.Errorf("duplicate digest %q found in array", h)
						}
						arrayDigests[h] = true

						info, exists := disclosureMap[h]
						if !exists {
							// Placeholder without disclosure is dropped (not revealed)
							continue
						}

						// Validate disclosure type matches context
						if !info.isArrayElem {
							return nil, fmt.Errorf("object field disclosure used in array context")
						}

						usedDisclosures[h] = true

						// Array-element disclosure
						processedVal, err := processNode(info.value, disclosureMap, usedDisclosures, config)
						if err != nil {
							return nil, err
						}
						out = append(out, processedVal)
						continue
					}
				}
			}

			processedElem, err := processNode(elem, disclosureMap, usedDisclosures, config)
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
