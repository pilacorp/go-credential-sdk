package sdjwt

import (
	"fmt"

	"github.com/pilacorp/go-credential-sdk/credential/common/util"
)

// Reconstruct rebuilds the processed SD-JWT payload from a vcMap containing
// SD-JWT digests and the provided disclosures.
//
// If validateAlg is true, validates that _sd_alg matches a supported hash algorithm.
func Reconstruct(vcMap map[string]interface{}, disclosures []string, validateAlg bool) (map[string]interface{}, error) {
	// Get and validate hash algorithm
	sdAlg, err := validateAndGetAlgorithm(vcMap, validateAlg)
	if err != nil {
		return nil, err
	}

	// Parse all disclosures into a map keyed by their hash
	disclosureMap, err := buildDisclosureMap(disclosures, sdAlg)
	if err != nil {
		return nil, err
	}

	// Deep copy vcMap to avoid modifying original
	rootCopy := util.DeepCopyMap(vcMap)

	// Process the SD-JWT structure, replacing digests with actual values
	processed, err := processNode(rootCopy, disclosureMap)
	if err != nil {
		return nil, err
	}

	// Ensure result is a map
	result, ok := processed.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("processed payload is not an object")
	}

	// Remove top-level _sd_alg if present
	delete(result, "_sd_alg")

	return result, nil
}

// validateAndGetAlgorithm extracts and validates the hash algorithm from vcMap.
func validateAndGetAlgorithm(vcMap map[string]interface{}, validateAlg bool) (string, error) {
	sdAlg := DefaultHashAlgorithm
	if v, ok := vcMap["_sd_alg"].(string); ok && v != "" {
		sdAlg = v
	}

	if validateAlg && !supportedHashAlgorithms[sdAlg] {
		return "", fmt.Errorf("unsupported _sd_alg: %q", sdAlg)
	}

	return sdAlg, nil
}

// buildDisclosureMap parses all disclosures and builds a hash -> disclosure mapping.
// This wraps the core parseDisclosure function and hashes each disclosure.
func buildDisclosureMap(disclosures []string, sdAlg string) (map[string]disclosureInfo, error) {
	disclosureMap := make(map[string]disclosureInfo, len(disclosures))

	for _, disc := range disclosures {
		if disc == "" {
			continue
		}

		// Hash the disclosure
		h, err := hashDisclosure(sdAlg, disc)
		if err != nil {
			return nil, fmt.Errorf("failed to hash disclosure: %w", err)
		}

		// Decode and parse disclosure (using core parseDisclosure from helper.go)
		info, err := parseDisclosure(disc)
		if err != nil {
			return nil, err
		}

		disclosureMap[h] = info
	}

	return disclosureMap, nil
}

// processNode recursively processes objects/arrays, applying disclosures.
func processNode(node interface{}, disclosureMap map[string]disclosureInfo) (interface{}, error) {
	switch v := node.(type) {
	case map[string]interface{}:
		// Handle _sd on this object first
		if rawSd, ok := v["_sd"]; ok {
			// Track all digests in this object to check for duplicates
			objectDigests := make(map[string]bool)

			switch sdList := rawSd.(type) {
			case []interface{}:
				// Convert to []string for uniform processing
				hashes := make([]string, 0, len(sdList))
				for _, item := range sdList {
					if h, ok := item.(string); ok {
						hashes = append(hashes, h)
					}
				}
				if err := applySDHashes(hashes, v, disclosureMap, objectDigests); err != nil {
					return nil, err
				}
			case []string:
				if err := applySDHashes(sdList, v, disclosureMap, objectDigests); err != nil {
					return nil, err
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
							// Placeholder without disclosure - keep it to preserve array structure
							out = append(out, map[string]interface{}{"...": h})
							continue
						}

						// Validate disclosure type matches context
						if !info.isArrayElem {
							return nil, fmt.Errorf("object field disclosure used in array context")
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

// applySDHashes processes a slice of hash strings, applying their disclosures to the object.
func applySDHashes(hashes []string, v map[string]interface{}, disclosureMap map[string]disclosureInfo, objectDigests map[string]bool) error {
	for _, h := range hashes {
		// Check for duplicate digest within this object
		if objectDigests[h] {
			return fmt.Errorf("duplicate digest %q found in _sd array", h)
		}
		objectDigests[h] = true

		info, ok := disclosureMap[h]
		if !ok {
			// No disclosure for this digest - it's either unrevealed or a decoy
			continue
		}

		// Validate disclosure type matches context
		if info.isArrayElem || info.objectField == "" {
			return fmt.Errorf("array element disclosure used in object context")
		}

		if _, exists := v[info.objectField]; exists {
			return fmt.Errorf("duplicate field %q when reconstructing SD-JWT object", info.objectField)
		}

		processedVal, err := processNode(info.value, disclosureMap)
		if err != nil {
			return err
		}
		v[info.objectField] = processedVal
	}
	return nil
}
