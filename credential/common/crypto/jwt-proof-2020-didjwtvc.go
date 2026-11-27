package crypto

import (
	"fmt"
	"sort"

	"github.com/pilacorp/go-credential-sdk/credential/internal/didjwtvc"
)

// A JwtProof2020 body that fails the VCDM 1.1 §6.3.1 mapping check is
// accepted when it equals what did-jwt-vc, the library that defined
// JwtProof2020, gives for the signed JWT (internal/didjwtvc). That object
// keeps the claims §6.3.1 does not map to a data model property (iat, aud,
// nonce) and keeps some members of the vc or vp claim nested beside the
// top-level ones. Every member of it comes from the signed payload.

// didJwtVcForm decodes claims as did-jwt-vc does and reports whether body,
// without its proof, is that object.
func didJwtVcForm(claims, body map[string]interface{}, isVP bool) (didjwtvc.Decoded, bool) {
	decode := didjwtvc.DecodeCredential
	if isVP {
		decode = didjwtvc.DecodePresentation
	}
	d, err := decode(claims)
	if err != nil || !jsonDeepEqual(withoutProof(body), withoutProof(d.Form)) {
		return didjwtvc.Decoded{}, false
	}
	return d, true
}

// checkNestedMembers checks that each member of the vc or vp claim the
// decoder left nested or overrode says the same as the top-level member a
// reader sees: later checks read the top level, the SDK's VC-JWT path reads
// the vc claim. Members are taken in sorted order, so the one an error names
// does not change from run to run.
func checkNestedMembers(d didjwtvc.Decoded) error {
	members := make([]string, 0, len(d.Nested))
	for member := range d.Nested {
		members = append(members, member)
	}
	sort.Strings(members)
	for _, member := range members {
		top, present := memberAt(d.Form, member)
		for _, v := range d.Nested[member] {
			if !present || !sameMembers(member, top, v) {
				return disagreeErr(member)
			}
		}
	}
	return nil
}

func withoutProof(m map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		if k != "proof" {
			out[k] = v
		}
	}
	return out
}

func disagreeErr(member string) error {
	return fmt.Errorf("member %q differs from another signed value in the JWT: %w", shownValue(member), ErrJwtProofBinding)
}
