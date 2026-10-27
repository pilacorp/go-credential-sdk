// Package jws signs and verifies JSON Web Signatures in the JWS Compact
// Serialization (RFC 7515 §7.1) with ES256, ECDSA P-256 SHA-256 (RFC 7518
// §3.4), and ES256K, ECDSA secp256k1 SHA-256 (RFC 8812 §3.2).
package jws

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"fmt"
	"slices"
	"strings"

	"github.com/pilacorp/go-credential-sdk/jose"
	"github.com/pilacorp/go-credential-sdk/jose/internal/ec"
	"github.com/pilacorp/go-credential-sdk/jose/internal/errtext"
)

const (
	AlgES256  = "ES256"  // ECDSA P-256 with SHA-256 (RFC 7518 §3.4)
	AlgES256K = "ES256K" // ECDSA secp256k1 with SHA-256 (RFC 8812 §3.2)
)

// maxHeaderBytes bounds the decoded JOSE Header. No standard sets a size; this
// is a resource bound: every reader decodes and parses the header as JSON
// before any signature is checked. An x5c chain fits many times over.
const maxHeaderBytes = 64 << 10

// maxHeaderSegment is the base64url length of maxHeaderBytes without padding,
// ceil(4n/3), so parse refuses an oversized header before decoding it.
const maxHeaderSegment = (4*maxHeaderBytes + 2) / 3

// Signer signs a 32-byte SHA-256 digest and returns the signature as 64-byte
// r||s, 32 bytes each (RFC 7518 §3.4, RFC 8812 §3.2). The private key stays
// with the signer (in memory, a key management service or an HSM). Sign uses
// the answer as is, so DER or r||s||v fails with ErrSelfCheck.
type Signer interface {
	Sign(digest []byte) ([]byte, error)
}

// Header is a decoded JOSE Header (RFC 7515 §4).
type Header map[string]any

// Alg returns the alg member, or "" when absent or not a string.
func (h Header) Alg() string { return h.str("alg") }

// Typ returns the typ member, or "" when absent or not a string.
func (h Header) Typ() string { return h.str("typ") }

// Kid returns the kid member, or "" when absent or not a string.
func (h Header) Kid() string { return h.str("kid") }

// TypIs reports whether the typ member names mediaType, for applications that
// use explicit typing (RFC 8725 §3.11). As RFC 7515 §4.1.9 says, case is
// ignored and a value without '/' on either side means "application/" + value.
// It is false when typ is absent, not a string or empty, when mediaType is
// empty, and when either carries parameters (';').
func (h Header) TypIs(mediaType string) bool {
	typ, ok := fullMediaType(h.Typ())
	want, wantOK := fullMediaType(mediaType)
	return ok && wantOK && equalFoldASCII(typ, want)
}

// fullMediaType applies RFC 7515 §4.1.9: a recipient MUST treat a value
// without '/' as if "application/" were prepended. A value with parameters is
// refused: the explicit types this SDK reads (kb+jwt, RFC 9901 §11.2.3;
// dc+sd-jwt, draft-ietf-oauth-sd-jwt-vc-19 §9.2.1; statuslist+jwt,
// draft-ietf-oauth-status-list-21 §14.7) register no parameters, so this
// matches their registrations.
func fullMediaType(v string) (string, bool) {
	if v == "" || strings.Contains(v, ";") {
		return "", false
	}
	if !strings.Contains(v, "/") {
		return "application/" + v, true
	}
	return v, true
}

// equalFoldASCII compares ignoring ASCII case only (RFC 7515 §4.1.9: media
// type values are case insensitive). strings.EqualFold also folds Unicode, so
// U+212A KELVIN SIGN would equal "k" and a non-ASCII typ could match.
func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if lowerASCII(a[i]) != lowerASCII(b[i]) {
			return false
		}
	}
	return true
}

func lowerASCII(c byte) byte {
	if 'A' <= c && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}

func (h Header) str(name string) string {
	s, _ := h[name].(string)
	return s
}

// Sign builds a compact JWS over payload (RFC 7515 §5.1, §7.1), signed by s
// with the private key of pub:
//  1. pub decides alg: ES256 on P-256, ES256K on secp256k1 (RFC 7518 §3.4,
//     RFC 8812 §3.2); an alg the caller put in header must equal it;
//  2. the header is encoded with jose.EncodeJSON (no HTML escaping, UTF-8
//     kept), must be at most 64 KiB and must read back with
//     jose.DecodeJSONObject, as Verify reads it; a header with crit or b64 is
//     refused by the check Verify applies. These are jose.ErrInvalidArgument
//     or ErrUnsupportedHeader, returned before s is called;
//  3. payload is signed exactly as given, never re-encoded; it may be empty;
//  4. the SHA-256 digest of base64url(header) "." base64url(payload) goes to
//     s, and its answer becomes the signature unchanged;
//  5. the token must verify with pub (Verify, alg as in step 1), else
//     ErrSelfCheck: this catches a signer holding another key and an answer
//     that is not 64-byte r||s.
func Sign(s Signer, pub *ecdsa.PublicKey, header Header, payload []byte) (string, error) {
	pt, err := ec.FromPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("%w: signer public key: %v", ErrBadKey, err)
	}
	alg := algOf(pt.Kind)
	if s == nil {
		return "", fmt.Errorf("%w: nil signer", jose.ErrInvalidArgument)
	}
	h := make(map[string]any, len(header)+1)
	for k, v := range header {
		h[k] = v
	}
	// RFC 7515 §5.1 step 5: alg must accurately represent the algorithm used;
	// RFC 8725 §3.1: the header alg is the algorithm of the operation.
	if v, ok := h["alg"]; ok && v != alg {
		got := fmt.Sprintf("of type %T", v)
		if s, ok := v.(string); ok {
			got = errtext.Quote(s)
		}
		return "", fmt.Errorf("%w: header alg %s differs from %q, the alg of the signer's key", jose.ErrInvalidArgument, got, alg)
	}
	if err := checkHeaderExtensions(h); err != nil {
		return "", err
	}
	h["alg"] = alg

	headerJSON, err := jose.EncodeJSON(h)
	if err != nil {
		return "", fmt.Errorf("header: %w", err)
	}
	if len(headerJSON) > maxHeaderBytes {
		return "", fmt.Errorf("%w: header is %d bytes; Verify reads at most %d", jose.ErrInvalidArgument, len(headerJSON), maxHeaderBytes)
	}
	// A header Verify cannot read (too deep, or a json.RawMessage with a
	// duplicate key) would cost a signer call and then fail the self-check.
	if _, err := jose.DecodeJSONObject(headerJSON); err != nil {
		return "", fmt.Errorf("%w: header: %v", jose.ErrInvalidArgument, err)
	}
	// RFC 7515 §5.1 steps 2, 4 and 5: the JWS Signing Input, hashed with
	// SHA-256 (RFC 7518 §3.4, RFC 8812 §3.2 step 1).
	signingInput := jose.EncodeSegment(headerJSON) + "." + jose.EncodeSegment(payload)
	digest := sha256.Sum256([]byte(signingInput))

	sig, err := s.Sign(digest[:])
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrSigner, err)
	}
	// RFC 7515 §5.1 step 8: the JWS Compact Serialization.
	token := signingInput + "." + jose.EncodeSegment(sig)
	// %v, not %w: the fault is the signer's, so the error must not also match
	// ErrBadSignature, which means a received token is bad.
	if _, _, err := Verify(token, pub, []string{alg}); err != nil {
		return "", fmt.Errorf("%w: %v", ErrSelfCheck, err)
	}
	return token, nil
}

// Verify checks a compact JWS against key and returns its header and the
// original payload bytes (not decoded as JSON):
//  1. exactly three dot-separated parts, each strict base64url; the payload
//     may be empty; the header is at most 64 KiB decoded;
//  2. the header is a JSON object (jose.DecodeJSON rules) with a string alg;
//  3. crit or b64 is ErrUnsupportedHeader;
//  4. the key is never taken from the header: jwk, x5c, jku and x5u are
//     ignored. RFC 7515 §6 and §10.3: the caller supplies the key from a
//     source whose origin it has authenticated;
//  5. alg must be ES256 or ES256K (none, HS*, RS*, PS*, EdDSA are refused even
//     if listed) and in allowed (nil or empty means both); the key decides the
//     algorithm, P-256 ⇒ ES256, secp256k1 ⇒ ES256K, else ErrAlgKeyMismatch;
//  6. the signature is exactly 64 bytes (no DER, no 65-byte r||s||v),
//     r and s in [1, n-1], else ErrBadSignature;
//  7. SHA-256 over the received header.payload string. Low-S and high-S both
//     verify: RFC 7518 §3.4 and RFC 8812 §3.2 put no limit on s beyond ECDSA
//     verification, which accepts any s in [1, n-1] (FIPS 186-5 §6.4.2 step
//     1).
func Verify(compact string, key *ecdsa.PublicKey, allowed []string) (Header, []byte, error) {
	tok, err := parse(compact)
	if err != nil {
		return nil, nil, err
	}
	header, alg, sig := tok.header, tok.header.Alg(), tok.sig

	// RFC 7515 §5.2 (last paragraph), RFC 7518 §8.5 and RFC 8725 §3.1: the
	// caller names the algorithms it accepts; only ES256 and ES256K ever are,
	// so none (RFC 7518 §3.6) is never accepted.
	if !isSupportedAlg(alg) {
		return nil, nil, fmt.Errorf("%w: %s", ErrAlgNotAllowed, errtext.Quote(alg))
	}
	if len(allowed) > 0 && !slices.Contains(allowed, alg) {
		return nil, nil, fmt.Errorf("%w: %s is not in the allowed list", ErrAlgNotAllowed, errtext.Quote(alg))
	}
	pt, err := ec.FromPublicKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrBadKey, err)
	}
	// RFC 7518 §3.4 and RFC 8812 §3.2, §3.3: ES256 is P-256 only and ES256K
	// is secp256k1 only, so the key decides the algorithm (RFC 8725 §3.1: one
	// algorithm per key, checked when the key is used).
	if algOf(pt.Kind) != alg {
		return nil, nil, fmt.Errorf("%w: header alg %q, key on %s", ErrAlgKeyMismatch, alg, pt.Kind.Name())
	}

	// RFC 7518 §3.4 validation step 1: the signature MUST be a 64-octet
	// sequence; RFC 8812 §3.2 step 4 defines the ES256K signature as the same
	// 64-octet R||S.
	if len(sig) != 64 {
		return nil, nil, fmt.Errorf("%w: signature is %d bytes, want 64-byte r||s", ErrBadSignature, len(sig))
	}

	// RFC 7515 §5.2 step 8, RFC 7518 §3.4 and RFC 8812 §3.2 step 1: SHA-256
	// over the received header.payload string, the JWS Signing Input.
	digest := sha256.Sum256([]byte(tok.signingInput))
	if err := pt.VerifyRS(digest[:], sig); err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrBadSignature, err)
	}
	return header, tok.payload, nil
}

// UnverifiedHeader returns the header of a compact JWS without checking its
// signature, so a caller can choose the key, by kid (RFC 7515 §4.1.4) for
// instance, before calling Verify with it. It refuses the same malformed
// tokens as Verify, with the same errors (steps 1 to 3: three parts,
// base64url, a header that is a JSON object, alg a string, crit and b64);
// whether alg is supported, allowed and matches the key is checked by Verify
// only. The header is untrusted until Verify succeeds: anyone can write any
// kid, typ or alg into it.
func UnverifiedHeader(compact string) (Header, error) {
	tok, err := parse(compact)
	if err != nil {
		return nil, err
	}
	return tok.header, nil
}

// UnverifiedPayload returns the payload of a compact JWS without checking its
// signature, for a reader that needs the claims before or without Verify: a
// Holder selecting disclosures, or a Verifier choosing the key by iss. It
// refuses the same malformed tokens as UnverifiedHeader, with the same errors.
// The payload is untrusted until Verify succeeds.
func UnverifiedPayload(compact string) ([]byte, error) {
	tok, err := parse(compact)
	if err != nil {
		return nil, err
	}
	return tok.payload, nil
}

// parsed is a compact JWS taken apart, before any check of alg, key or
// signature.
type parsed struct {
	header       Header
	payload, sig []byte
	signingInput string // the received header.payload (RFC 7515 §5.2 step 8)
}

// parse holds the structural checks of Verify (steps 1 to 3), so every
// function that reads a compact JWS rejects the same malformed tokens with the
// same errors. alg is not checked against the supported or allowed list here.
func parse(compact string) (parsed, error) {
	// RFC 7515 §5.2 step 1 and §7.1: three parts separated by exactly two
	// periods. SplitN, not Split: a megabyte of dots must not become a million
	// strings before the count is checked.
	parts := strings.SplitN(compact, ".", 4)
	if len(parts) != 3 {
		return parsed{}, fmt.Errorf("%w: a compact JWS has three parts", jose.ErrMalformed)
	}
	if len(parts[0]) > maxHeaderSegment {
		return parsed{}, fmt.Errorf("%w: header is over %d bytes, the most this package reads", jose.ErrMalformed, maxHeaderBytes)
	}
	// RFC 7515 §5.2 steps 2, 6 and 7: strict base64url, no line breaks.
	headerJSON, err := jose.DecodeSegment(parts[0])
	if err != nil {
		return parsed{}, fmt.Errorf("header: %w", err)
	}
	payload, err := jose.DecodeSegment(parts[1])
	if err != nil {
		return parsed{}, fmt.Errorf("payload: %w", err)
	}
	sig, err := jose.DecodeSegment(parts[2])
	if err != nil {
		return parsed{}, fmt.Errorf("signature: %w", err)
	}
	// RFC 7515 §5.2 steps 3 and 4: a valid JSON object without duplicate
	// Header Parameter names.
	obj, err := jose.DecodeJSONObject(headerJSON)
	if err != nil {
		return parsed{}, fmt.Errorf("header: %w", err)
	}
	header := Header(obj)
	// RFC 7515 §4.1.1: alg MUST be present; its value is a string.
	if _, ok := header["alg"].(string); !ok {
		return parsed{}, fmt.Errorf("%w: header alg must be a string", jose.ErrMalformed)
	}
	if err := checkHeaderExtensions(header); err != nil {
		return parsed{}, err
	}
	return parsed{header: header, payload: payload, sig: sig, signingInput: parts[0] + "." + parts[1]}, nil
}

// checkHeaderExtensions refuses a header that has crit or b64, whatever their
// value: this package implements no extension crit can list, and not b64
// (RFC 7797). RFC 7515 §4.1.11: a JWS whose crit lists an extension the
// recipient does not support is invalid. A b64 without crit, or crit [], also
// breaks a producer MUST (RFC 7797 §6, RFC 7515 §4.1.11), but the class stays
// ErrUnsupportedHeader: a recipient that implements b64 could still process
// such a token, so the refusal says what this package lacks.
func checkHeaderExtensions(h map[string]any) error {
	if _, ok := h["crit"]; ok {
		return fmt.Errorf("%w: crit", ErrUnsupportedHeader)
	}
	if _, ok := h["b64"]; ok {
		return fmt.Errorf("%w: b64", ErrUnsupportedHeader)
	}
	return nil
}

// algOf panics on an invalid kind, like ec.Kind.Name.
func algOf(k ec.Kind) string {
	switch k {
	case ec.P256:
		return AlgES256
	case ec.Secp256k1:
		return AlgES256K
	}
	panic(fmt.Sprintf("jose: invalid curve kind %d", k))
}

func isSupportedAlg(alg string) bool {
	return alg == AlgES256 || alg == AlgES256K
}
