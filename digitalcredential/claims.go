// The claims draft-ietf-oauth-sd-jwt-vc-19 fixes for every SD-JWT VC: the typ
// header (§2.2.1) and the claims that must not be concealed (§2.2.2.3).

package dc

// typDCSDJWT: draft 19 §2.2.1, the typ header MUST be dc+sd-jwt.
const typDCSDJWT = "dc+sd-jwt"

// neverDisclosable holds the eight claims draft 19 §2.2.2.3 says MUST NOT be
// included in Disclosures, sub-claims included. All are top-level claims, so
// a path is judged by its first element.
var neverDisclosable = map[string]bool{
	"iss":           true,
	"nbf":           true,
	"exp":           true,
	"cnf":           true,
	"vct":           true,
	"vct#integrity": true,
	"aka_vcts":      true,
	"status":        true,
}
