package sdjwt

import (
	"fmt"
	"math"
	"unicode/utf8"

	"github.com/pilacorp/go-credential-sdk/credential/internal/jwtutil"
	"github.com/pilacorp/go-credential-sdk/jose"
	josesdjwt "github.com/pilacorp/go-credential-sdk/jose/sdjwt"
)

// Reconstruct rebuilds the payload of an SD-JWT from its Issuer-signed JWT
// payload and the disclosures received with it, through
// jose/sdjwt.RecreateWithOptions (RFC 9901 §7.1 steps 3 to 5) with sha-256,
// sha-384 and sha-512 accepted. Empty disclosure strings are skipped. vcMap is
// not modified, and the result has no _sd, "..." or _sd_alg. Numbers come back
// as float64, as encoding/json decodes them, whether disclosed or not.
//
// validateAlg is deprecated and has no effect: an _sd_alg outside those three
// is always refused, even with no disclosure, since no digest can be checked
// under it.
func Reconstruct(vcMap map[string]interface{}, disclosures []string, validateAlg bool) (map[string]interface{}, error) {
	_ = validateAlg
	// Parsed first, so a disclosure naming a reserved claim is refused for its
	// name even when no digest matches it; §7.1 step 5 would refuse it anyway
	// (RFC 9901 §7.1 step 3c.ii.2 names _sd and ... for a referenced one).
	given := make([]josesdjwt.Disclosure, 0, len(disclosures))
	for _, d := range disclosures {
		if d == "" {
			continue
		}
		p, err := josesdjwt.ParseDisclosure(d)
		if err != nil {
			return nil, fmt.Errorf("decode disclosure: %w", err)
		}
		given = append(given, p)
	}
	// Read as JSON, as the payload will be once signed, whatever Go types
	// vcMap holds ([]string for _sd, typed maps, structs). A payload a parser
	// just decoded is JSON already and is not copied again.
	payload := vcMap
	if !isJSONTree(vcMap, 0) {
		var err error
		if payload, err = jsonTree(vcMap); err != nil {
			return nil, err
		}
	}
	r, err := josesdjwt.RecreateWithOptions(payload, given, josesdjwt.RecreateOptions{Algorithms: supportedHashAlgorithms})
	if err != nil {
		return nil, err
	}
	// Converted in place: jose shares Claims only with r's Issued tree, and
	// r is dropped here, so nothing else sees the change.
	if err := jwtutil.FloatNumbersInPlace(r.Claims); err != nil {
		return nil, err
	}
	return r.Claims, nil
}

// isJSONTree reports whether v is a tree jwtutil.DecodeJSONObject returns:
// non-nil objects and arrays, valid UTF-8 keys and strings, finite float64
// numbers, booleans and null, no deeper than jose's JSON reader allows. Such
// a tree reads the same through jsonTree, so the copy is skipped; anything
// else goes through jsonTree, which normalizes or refuses it.
func isJSONTree(v interface{}, depth int) bool {
	if depth >= jose.MaxJSONDepth {
		return false
	}
	switch t := v.(type) {
	case map[string]interface{}:
		if t == nil {
			return false
		}
		for k, el := range t {
			if !utf8.ValidString(k) || !isJSONTree(el, depth+1) {
				return false
			}
		}
	case []interface{}:
		if t == nil {
			return false
		}
		for _, el := range t {
			if !isJSONTree(el, depth+1) {
				return false
			}
		}
	case float64:
		return !math.IsNaN(t) && !math.IsInf(t, 0)
	case string:
		return utf8.ValidString(t)
	case bool, nil:
	default:
		return false
	}
	return true
}
