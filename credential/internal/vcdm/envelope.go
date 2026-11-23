package vcdm

import "strings"

// Media types an EnvelopedVerifiableCredential's data: URL may name (VCDM 2.0
// §4.13): a credential secured with vc-jose-cose, as a JWS, an SD-JWT or a
// COSE_Sign1. A COSE token is binary, so its data: URL is base64.
const (
	MediaTypeVCJWT   = "vc+jwt"
	MediaTypeVCSDJWT = "vc+sd-jwt"
	MediaTypeVCCOSE  = "vc+cose"
)

// CutEnvelopedDataURL splits the id of an enveloped credential,
// data:application/vc+jwt,<token>, data:application/vc+sd-jwt,<token> or
// data:application/vc+cose;base64,<base64>, into its media type and token
// (still base64 for vc+cose). The scheme (RFC 3986 §3.1) and the media type
// (RFC 2045 §5.1) match in any case; the token is returned as written and may
// be empty, which the caller refuses. ok is false for any other id.
//
// Every place that reads an envelope uses this one function, so the gate that
// accepts an envelope and the code that opens it cannot disagree.
func CutEnvelopedDataURL(id string) (mediaType, token string, ok bool) {
	for _, mt := range []struct{ name, prefix string }{
		{MediaTypeVCJWT, "data:application/" + MediaTypeVCJWT + ","},
		{MediaTypeVCSDJWT, "data:application/" + MediaTypeVCSDJWT + ","},
		{MediaTypeVCCOSE, "data:application/" + MediaTypeVCCOSE + ";base64,"},
	} {
		if len(id) >= len(mt.prefix) && strings.EqualFold(id[:len(mt.prefix)], mt.prefix) {
			return mt.name, id[len(mt.prefix):], true
		}
	}
	return "", "", false
}
