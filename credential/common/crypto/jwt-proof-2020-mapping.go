package crypto

import (
	"strings"
	"time"

	"github.com/pilacorp/go-credential-sdk/credential/internal/jwtutil"
	"github.com/pilacorp/go-credential-sdk/credential/internal/vcdm"
)

// The VCDM 1.1 §6.3.1 mapping check: a JwtProof2020 body binds to its JWT
// when each member is in the vc or vp claim or moved to the registered claim
// the data model names, and no signed claim is left out of the body. When a
// member and its registered claim are both there, the decoding text sets the
// member from the claim, so the two must agree (checkRegisteredClaims).
//
// §6.3.1 decoding puts exp in "the expirationDate property of
// credentialSubject"; its encoding row ("exp MUST represent the
// expirationDate property"), did-jwt-vc and this SDK put it at the top level,
// which is what this file reads.

// movedMember is a top-level member that a registered JWT claim carries:
// issuer (iss), id (jti), credentialSubject.id (sub), issuanceDate (nbf) and
// expirationDate (exp) per VCDM 1.1 §6.3.1, and their VCDM 2.0 names
// validFrom and validUntil as this SDK's JWT paths write them
// (vc/jwt_credential.go, vp/jwt_presentation.go). For a presentation, holder
// (iss) and id (jti), issuanceDate and validFrom (nbf: §6.3.1 decoding sets
// the issuanceDate of "the new JSON object"), and expirationDate and
// validUntil (exp, as did-jwt-vc and the SDK's VP-JWT path write it).
//
// shown marks a member the body must show when its claim is signed (Check
// 5): one of them per claim. A move that is not shown is compared when both
// are there but not required: §6.3.1 decoding moves no exp of a presentation.
type movedMember struct {
	member, claim string
	shown         bool
}

// credentialMoves and presentationMoves are the one table of those moves, read
// by the mapping check and by checkRegisteredClaims.
var (
	credentialMoves = []movedMember{
		{"issuer", "iss", false}, {"id", "jti", true}, {"credentialSubject.id", "sub", false},
		{vcdm.IssuanceDate, "nbf", true}, {vcdm.ValidFrom, "nbf", true},
		{vcdm.ExpirationDate, "exp", true}, {vcdm.ValidUntil, "exp", true},
	}
	presentationMoves = []movedMember{
		{"holder", "iss", false}, {"id", "jti", true},
		{vcdm.IssuanceDate, "nbf", true}, {vcdm.ValidFrom, "nbf", true},
		{vcdm.ExpirationDate, "exp", false}, {vcdm.ValidUntil, "exp", false},
	}
)

func movesFor(isVP bool) []movedMember {
	if isVP {
		return presentationMoves
	}
	return credentialMoves
}

// claimFor returns the registered claim a member moves to.
func claimFor(moves []movedMember, member string) (string, bool) {
	for _, m := range moves {
		if m.member == member {
			return m.claim, true
		}
	}
	return "", false
}

// shownMembersFor returns the members that must be shown for claim, in table
// order.
func shownMembersFor(moves []movedMember, claim string) []string {
	var out []string
	for _, m := range moves {
		if m.claim == claim && m.shown {
			out = append(out, m.member)
		}
	}
	return out
}

// checkMappedBody is the VCDM 1.1 §6.3.1 mapping check: each body member is in the
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
			// VCDM 1.1 §6.3.1 moves to the sub claim.
			if !isVP && k == "credentialSubject" {
				if err := checkSubjectIDMovedToSub(bodyVal, cVal, claims); err != nil {
					return err
				}
				continue
			}
			return memberErr(k)
		}
		// Not in the container claim: check if it is a moved field.
		if err := checkMovedField(k, bodyVal, claims, movesFor(isVP)); err != nil {
			return err
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
	moves := movesFor(isVP)
	for _, claim := range []string{"jti", "nbf", "exp"} {
		members := shownMembersFor(moves, claim)
		if _, signed := claims[claim]; !signed || len(members) == 0 {
			continue
		}
		if !bodyHasAny(body, members) {
			return memberErr(members[0])
		}
	}
	if _, signed := claims["sub"]; signed && !isVP && !subjectHasID(body["credentialSubject"]) {
		return memberErr("credentialSubject")
	}
	return nil
}

// checkMovedField checks a body member absent from the vc or vp claim against
// the registered claim the moves table sends it to.
func checkMovedField(key string, bodyVal interface{}, claims map[string]interface{}, moves []movedMember) error {
	claim, moved := claimFor(moves, key)
	if !moved {
		return memberErr(key)
	}
	switch key {
	case "issuer":
		return checkMovedIssuer(bodyVal, claims)
	case "holder":
		return checkMovedHolder(bodyVal, claims)
	case "id":
		return checkStringClaim(key, bodyVal, claims, claim)
	default:
		if !memberMatchesClaim(key, bodyVal, claims[claim]) {
			return memberErr(key)
		}
		return nil
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
// JWT claim (VCDM 1.1 §6.3.1). When credentialSubject is an array, sub is
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
		// sub stands for the first subject. That is SDK policy: VCDM 1.1
		// §6.3.1 has no rule for several subjects, and its Note says a JWT
		// cannot encode them. checkSubjectIDMovedToSub compares sub with the
		// first element only, so an id on another subject must not stand in.
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

// checkRegisteredClaims checks that each registered claim and the member it
// carries say the same when both are there (VCDM 1.1 §6.3.1 decoding: the
// claim "MUST be used to set" the member), for the moves of one table.
func checkRegisteredClaims(claims, body map[string]interface{}, moves []movedMember) error {
	for _, m := range moves {
		claim, signed := claims[m.claim]
		member, present := memberAt(body, m.member)
		if signed && present && !memberMatchesClaim(m.member, member, claim) {
			return disagreeErr(m.member)
		}
	}
	return nil
}

// memberAt reads a top-level member, or for "credentialSubject.id" the id of
// the subject sub stands for: the object, or the first element of an array
// (subjectHasID).
func memberAt(body map[string]interface{}, member string) (interface{}, bool) {
	if inner, ok := strings.CutPrefix(member, "credentialSubject."); ok {
		subject := body["credentialSubject"]
		if list, isList := subject.([]interface{}); isList && len(list) > 0 {
			subject = list[0]
		}
		m, _ := subject.(map[string]interface{})
		v, present := m[inner]
		return v, present
	}
	v, present := body[member]
	return v, present
}

// sameMembers reports whether two member values of key say the same: for a
// date member, two dates (vcdm.ParseDateTime) at the same instant, since
// readers compare them to the nanosecond; otherwise equal JSON, or for issuer
// or holder an id string and an object with that id.
func sameMembers(key string, a, b interface{}) bool {
	if vcdm.IsDateMember(key) {
		ta, okA := memberTime(a)
		tb, okB := memberTime(b)
		return okA && okB && ta.Equal(tb)
	}
	return jsonDeepEqual(a, b) || ((key == "issuer" || key == "holder") && (idOf(a, b) || idOf(b, a)))
}

// memberMatchesClaim reports whether a member value of key says the same as
// the registered claim that carries it: for a date member, a date and a
// NumericDate at the same second, the precision of the claim, its fraction
// dropped as the JWT path does (jwtutil.NumericDate); otherwise as
// sameMembers. A member that is not a date, or a claim that is not a
// NumericDate, never matches, even when the two are equal.
func memberMatchesClaim(key string, member, claim interface{}) bool {
	if vcdm.IsDateMember(key) {
		tm, okM := memberTime(member)
		sc, errC := jwtutil.NumericDate(claim)
		return okM && errC == nil && tm.Unix() == sc
	}
	return sameMembers(key, member, claim)
}

// memberTime reads a date member, a string.
func memberTime(v interface{}) (time.Time, bool) {
	s, ok := v.(string)
	if !ok {
		return time.Time{}, false
	}
	t, err := vcdm.ParseDateTime(s)
	return t, err == nil
}

// idOf reports whether s is a string and obj an object with id s.
func idOf(s, obj interface{}) bool {
	id, ok := s.(string)
	m, _ := obj.(map[string]interface{})
	return ok && m["id"] == id
}
