package vcdm

import "strings"

// Media types an EnvelopedVerifiableCredential's data: URL may name (VCDM 2.0
// §4.13): a credential secured with vc-jose-cose, as a JWS or as an SD-JWT.
const (
	MediaTypeVCJWT   = "vc+jwt"
	MediaTypeVCSDJWT = "vc+sd-jwt"
)

// CutEnvelopedDataURL splits the id of an enveloped credential,
// data:application/vc+jwt,<token> or data:application/vc+sd-jwt,<token>, into
// its media type and token. The scheme (RFC 3986 §3.1) and the media type
// (RFC 2045 §5.1) match in any case; the token is returned as written and may
// be empty, which the caller refuses. ok is false for any other id.
//
// Every place that reads an envelope uses this one function, so the gate that
// accepts an envelope and the code that opens it cannot disagree.
func CutEnvelopedDataURL(id string) (mediaType, token string, ok bool) {
	for _, mt := range []string{MediaTypeVCJWT, MediaTypeVCSDJWT} {
		prefix := "data:application/" + mt + ","
		if len(id) >= len(prefix) && strings.EqualFold(id[:len(prefix)], prefix) {
			return mt, id[len(prefix):], true
		}
	}
	return "", "", false
}
