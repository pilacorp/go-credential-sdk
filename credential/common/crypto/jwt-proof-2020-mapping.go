package crypto

import (
	"math"

	"github.com/pilacorp/go-credential-sdk/credential/internal/vcdm"
)

// The VC-JWT 1.1 mapping check (VCDM 1.1 §6.3.1): a JwtProof2020 body binds to
// its JWT when each member is in the vc or vp claim or moved to the registered
// claim the data model names, and no signed claim is left out of the body.

// checkMappedBody is the VC-JWT 1.1 mapping check: each body member is in the
// vc/vp claim or moved to its registered claim, and nothing signed is dropped.
func checkMappedBody(body, container, claims map[string]interface{}, isVP bool) error {
	// Check 2: every body member (except proof) must be covered.
	for k, bodyVal := range body {
		if k == "proof" {
			continue
		}
		if cVal, inContainer := container[k]; inContainer {
			if jsonDeepEqual(bodyVal, cVal) {
				continue
			}
			// credentialSubject may differ only by the id field, which
			// VC-JWT 1.1 §6.3.1 moves to the sub claim.
			if !isVP && k == "credentialSubject" {
				if err := checkSubjectIDMovedToSub(bodyVal, cVal, claims); err != nil {
					return err
				}
				continue
			}
			return memberErr(k)
		}
		// Not in the container claim: check if it is a moved field.
		if isVP {
			if err := checkMovedFieldVP(k, bodyVal, claims); err != nil {
				return err
			}
		} else {
			if err := checkMovedField(k, bodyVal, claims); err != nil {
				return err
			}
		}
	}

	// Check 4: a container member that the body lacks, or a proof member
	// inside the container, makes the proof fail.
	for k := range container {
		if k == "proof" {
			return memberErr(k)
		}
		if _, inBody := body[k]; !inBody {
			return memberErr(k)
		}
	}

	// Check 5: each moved claim the JWT signs must have a corresponding
	// member in the body. Without this, a body that silently drops e.g.
	// expirationDate still verifies, and WithCheckExpiration (which reads
	// only the body) lets an expired credential through.
	if isVP {
		if _, ok := claims["jti"]; ok && body["id"] == nil {
			return memberErr("id")
		}
	} else {
		for claim, members := range map[string][]string{
			"jti": {"id"},
			"nbf": {"issuanceDate", "validFrom"},
			"exp": {"expirationDate", "validUntil"},
		} {
			if _, signed := claims[claim]; !signed {
				continue
			}
			if !bodyHasAny(body, members) {
				return memberErr(members[0])
			}
		}
		if _, signed := claims["sub"]; signed && !subjectHasID(body["credentialSubject"]) {
			return memberErr("credentialSubject")
		}
	}
	return nil
}

// checkMovedField checks whether a body member absent from the vc claim is
// accounted for by the VC-JWT 1.1 moved-field table.
func checkMovedField(key string, bodyVal interface{}, claims map[string]interface{}) error {
	switch key {
	case "issuer":
		return checkMovedIssuer(bodyVal, claims)
	case "id":
		return checkStringClaim(key, bodyVal, claims, "jti")
	case "issuanceDate", "validFrom":
		return checkTimeClaim(key, bodyVal, claims, "nbf")
	case "expirationDate", "validUntil":
		return checkTimeClaim(key, bodyVal, claims, "exp")
	default:
		return memberErr(key)
	}
}

// checkMovedFieldVP checks whether a body member absent from the vp claim is
// accounted for by the VC-JWT 1.1 §6.3.2 VP moved-field table:
// holder ↔ iss, id ↔ jti (no date fields).
func checkMovedFieldVP(key string, bodyVal interface{}, claims map[string]interface{}) error {
	switch key {
	case "holder":
		return checkMovedHolder(bodyVal, claims)
	case "id":
		return checkStringClaim(key, bodyVal, claims, "jti")
	default:
		return memberErr(key)
	}
}

// checkMovedIssuer validates the issuer field against iss.
// A string issuer must equal iss. An object issuer must have only "id"
// equal to iss; additional members like "name" are unsigned.
func checkMovedIssuer(bodyVal interface{}, claims map[string]interface{}) error {
	iss, _ := claims["iss"].(string)
	if iss == "" {
		return memberErr("issuer")
	}
	switch v := bodyVal.(type) {
	case string:
		if v != iss {
			return memberErr("issuer")
		}
		return nil
	case map[string]interface{}:
		if len(v) != 1 {
			return memberErr("issuer")
		}
		id, _ := v["id"].(string)
		if id != iss {
			return memberErr("issuer")
		}
		return nil
	default:
		return memberErr("issuer")
	}
}

// checkMovedHolder validates the VP holder field against iss.
func checkMovedHolder(bodyVal interface{}, claims map[string]interface{}) error {
	iss, _ := claims["iss"].(string)
	if iss == "" {
		return memberErr("holder")
	}
	s, ok := bodyVal.(string)
	if !ok || s != iss {
		return memberErr("holder")
	}
	return nil
}

// checkSubjectIDMovedToSub handles the case where credentialSubject is present
// in both body and vc but they differ because the id field was moved to the sub
// JWT claim (VC-JWT 1.1 §6.3.1). When credentialSubject is an array, sub is
// the id of the first element; the other elements must match as-is.
func checkSubjectIDMovedToSub(bodyVal, vcVal interface{}, claims map[string]interface{}) error {
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return memberErr("credentialSubject")
	}

	switch bv := bodyVal.(type) {
	case map[string]interface{}:
		vv, ok := vcVal.(map[string]interface{})
		if !ok {
			return memberErr("credentialSubject")
		}
		return checkSingleSubjectID(bv, vv, sub)

	case []interface{}:
		va, ok := vcVal.([]interface{})
		if !ok || len(bv) != len(va) {
			return memberErr("credentialSubject")
		}
		if len(bv) == 0 {
			return memberErr("credentialSubject")
		}
		// First element: id may be moved to sub.
		bFirst, ok1 := bv[0].(map[string]interface{})
		vFirst, ok2 := va[0].(map[string]interface{})
		if !ok1 || !ok2 {
			return memberErr("credentialSubject")
		}
		if err := checkSingleSubjectID(bFirst, vFirst, sub); err != nil {
			return err
		}
		// Remaining elements must match exactly.
		for i := 1; i < len(bv); i++ {
			if !jsonDeepEqual(bv[i], va[i]) {
				return memberErr("credentialSubject")
			}
		}
		return nil

	default:
		return memberErr("credentialSubject")
	}
}

// checkSingleSubjectID verifies that a body subject object equals the vc subject
// object except for the id field, which must equal sub.
func checkSingleSubjectID(bodySubject, vcSubject map[string]interface{}, sub string) error {
	bodyID, hasBodyID := bodySubject["id"].(string)
	_, hasVCID := vcSubject["id"]
	if !hasBodyID || hasVCID {
		// If body has no id, or vc already has id, this isn't the moved-id case.
		return memberErr("credentialSubject")
	}
	if bodyID != sub {
		return memberErr("credentialSubject")
	}
	// Every other field in the body subject must match vc subject.
	if len(bodySubject)-1 != len(vcSubject) {
		return memberErr("credentialSubject")
	}
	for k, bv := range bodySubject {
		if k == "id" {
			continue
		}
		vv, ok := vcSubject[k]
		if !ok || !jsonDeepEqual(bv, vv) {
			return memberErr("credentialSubject")
		}
	}
	return nil
}

// checkStringClaim checks a string body member against a string JWT claim.
func checkStringClaim(key string, bodyVal interface{}, claims map[string]interface{}, claimKey string) error {
	bodyStr, ok := bodyVal.(string)
	if !ok {
		return memberErr(key)
	}
	claimVal, _ := claims[claimKey].(string)
	if bodyStr != claimVal {
		return memberErr(key)
	}
	return nil
}

// checkTimeClaim checks an RFC 3339 date string in the body against a
// numeric Unix timestamp JWT claim (nbf or exp).
func checkTimeClaim(key string, bodyVal interface{}, claims map[string]interface{}, claimKey string) error {
	dateStr, ok := bodyVal.(string)
	if !ok {
		return memberErr(key)
	}
	t, err := vcdm.ParseDateTime(dateStr)
	if err != nil {
		return memberErr(key)
	}
	claimNum, ok := claims[claimKey].(float64)
	if !ok {
		return memberErr(key)
	}
	// A fractional, NaN, or Inf timestamp is not a valid second-precision
	// Unix time; refuse rather than silently truncating.
	if math.IsNaN(claimNum) || math.IsInf(claimNum, 0) || claimNum != math.Trunc(claimNum) {
		return memberErr(key)
	}
	if t.Unix() != int64(claimNum) {
		return memberErr(key)
	}
	return nil
}

// bodyHasAny returns true when the body contains at least one of the given keys.
func bodyHasAny(body map[string]interface{}, keys []string) bool {
	for _, k := range keys {
		if _, ok := body[k]; ok {
			return true
		}
	}
	return false
}

// subjectHasID reports whether the subject a signed sub stands for carries an
// "id": the object itself, or the first element of an array.
func subjectHasID(raw interface{}) bool {
	switch v := raw.(type) {
	case map[string]interface{}:
		_, ok := v["id"]
		return ok
	case []interface{}:
		// sub stands for the first subject: VC-JWT 1.1 moves that subject's id
		// into it, and checkSubjectIDMovedToSub compares it with the first
		// element only. An id on another subject must not stand in for it.
		if len(v) == 0 {
			return false
		}
		if m, ok := v[0].(map[string]interface{}); ok {
			_, hasID := m["id"]
			return hasID
		}
	}
	return false
}
