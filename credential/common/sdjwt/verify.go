package sdjwt

import (
	"fmt"
	"sort"
)

// ValidateDisclosureDigests checks that every disclosure travelling alongside an
// SD-JWT is actually referenced by a digest inside the issuer-signed payload.
//
// The issuer's signature only covers the digests, so a Holder (or anyone in the
// middle) can append arbitrary disclosure strings to the serialized SD-JWT
// without breaking the signature. Reconstruct silently ignores such orphan
// disclosures, which means a credential carrying forged claims would otherwise
// verify. Verifiers must therefore reject any disclosure whose digest the issuer
// did not sign.
//
// payload is the decoded JWT body (for VC JWTs the digests live under the "vc"
// claim; both placements are handled). Each disclosure must be well-formed, must
// hash — under the payload's _sd_alg — to a digest present in some "_sd" array or
// "..." array placeholder, and must not be presented twice.
func ValidateDisclosureDigests(payload map[string]interface{}, disclosures []string) error {
	if len(disclosures) == 0 {
		return nil
	}

	sdAlg, err := payloadHashAlgorithm(payload)
	if err != nil {
		return err
	}

	signedDigests := make(map[string]bool)
	collectDigests(payload, signedDigests)

	seen := make(map[string]bool, len(disclosures))
	for _, disc := range disclosures {
		if disc == "" {
			continue
		}

		info, err := parseDisclosure(disc)
		if err != nil {
			return err
		}

		h, err := hashDisclosure(sdAlg, disc)
		if err != nil {
			return fmt.Errorf("failed to hash disclosure: %w", err)
		}

		if seen[h] {
			return fmt.Errorf("disclosure %q is presented more than once", disclosureLabel(info))
		}
		seen[h] = true

		if !signedDigests[h] {
			return fmt.Errorf("disclosure %q has digest %q, which is not present in the issuer-signed payload", disclosureLabel(info), h)
		}
	}

	return nil
}

// payloadHashAlgorithm resolves the _sd_alg governing the payload's digests.
// The claim is looked up anywhere in the payload, since this SDK writes it into
// the "vc" claim while RFC 9901 puts it at the top level. Conflicting values are
// rejected rather than guessed at.
func payloadHashAlgorithm(payload map[string]interface{}) (string, error) {
	found := make(map[string]bool)
	collectHashAlgorithms(payload, found)

	switch len(found) {
	case 0:
		return DefaultHashAlgorithm, nil
	case 1:
		var sdAlg string
		for alg := range found {
			sdAlg = alg
		}
		if !supportedHashAlgorithms[sdAlg] {
			return "", fmt.Errorf("unsupported _sd_alg: %q", sdAlg)
		}
		return sdAlg, nil
	default:
		algs := make([]string, 0, len(found))
		for alg := range found {
			algs = append(algs, alg)
		}
		sort.Strings(algs)
		return "", fmt.Errorf("conflicting _sd_alg values in payload: %v", algs)
	}
}

// collectHashAlgorithms gathers every non-empty _sd_alg string in the tree.
func collectHashAlgorithms(node interface{}, out map[string]bool) {
	switch v := node.(type) {
	case map[string]interface{}:
		if alg, ok := v["_sd_alg"].(string); ok && alg != "" {
			out[alg] = true
		}
		for _, val := range v {
			collectHashAlgorithms(val, out)
		}
	case []interface{}:
		for _, elem := range v {
			collectHashAlgorithms(elem, out)
		}
	}
}

// collectDigests gathers every digest the issuer committed to: the entries of
// each "_sd" array and each { "...": digest } array placeholder.
func collectDigests(node interface{}, out map[string]bool) {
	switch v := node.(type) {
	case map[string]interface{}:
		switch sd := v["_sd"].(type) {
		case []interface{}:
			for _, item := range sd {
				if h, ok := item.(string); ok {
					out[h] = true
				}
			}
		case []string:
			for _, h := range sd {
				out[h] = true
			}
		}

		if len(v) == 1 {
			if h, ok := v["..."].(string); ok {
				out[h] = true
			}
		}

		for key, val := range v {
			if key == "_sd" {
				continue
			}
			collectDigests(val, out)
		}

	case []interface{}:
		for _, elem := range v {
			collectDigests(elem, out)
		}
	}
}

// disclosureLabel describes a disclosure in error messages without echoing the
// (potentially large) raw base64url string or the claim value itself.
func disclosureLabel(info disclosureInfo) string {
	if info.isArrayElem {
		return "array element"
	}
	return info.objectField
}
