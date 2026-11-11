// Package jws signs and verifies JSON Web Signatures in the JWS Compact
// Serialization (RFC 7515 §7.1) with ES256, ECDSA P-256 SHA-256 (RFC 7518
// §3.4), and ES256K, ECDSA secp256k1 SHA-256 (RFC 8812 §3.2).
package jws

import (
	"context"
	"crypto"
	"crypto/sha256"
	"errors"
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

// Header is a decoded JOSE Header (RFC 7515 §4).
type Header map[string]any

// Alg returns the alg member, or "" when absent or not a string.
func (h Header) Alg() string { return h.str("alg") }

// Typ returns the typ member, or "" when absent or not a string.
func (h Header) Typ() string { return h.str("typ") }

// Kid returns the kid member, or "" when absent or not a string.
func (h Header) Kid() string { return h.str("kid") }

// TypIs reports whether the typ member names mediaType, for applications that
// use explicit typing (RFC 8725 §3.11). Case is ignored, and RFC 7515 §4.1.9
// says a recipient treats a typ without '/' as "application/" + value;
// mediaType is read the same way.
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

// Sign builds a compact JWS over payload (RFC 7515 §5.1, §7.1), signed by s,
// whose key pub is. It checks, in this order, and returns before s is called:
//  1. pub is an *ecdsa.PublicKey on P-256 or secp256k1, else
//     jose.ErrUnsupportedKey; nil or not on its curve is ErrBadKey; a nil s
//     or a nil ctx is jose.ErrInvalidArgument;
//  2. s.Alg() is ES256 or ES256K, else jose.ErrUnsupportedAlg, and matches
//     the curve of pub (ES256 on P-256, ES256K on secp256k1, RFC 7518 §3.4,
//     RFC 8812 §3.2), else ErrAlgKeyMismatch (RFC 8725 §3.1); an alg the
//     caller put in header must equal it, else jose.ErrInvalidArgument;
//  3. a header with crit or b64 is ErrUnsupportedHeader, as Verify refuses it;
//  4. the header, encoded with jose.EncodeJSON, is at most 64 KiB and reads
//     back with jose.DecodeJSONObject as Verify reads it, else
//     jose.ErrInvalidArgument.
//
// Then s.Sign gets ctx and the JWS Signing Input, base64url(header) "."
// base64url(payload), with payload signed exactly as given. Sign itself does
// no I/O and leaves ctx to s. An error from s is ErrSignerFailed wrapping
// that error, so a ctx that ends inside s matches context.Canceled or
// context.DeadlineExceeded too. Its answer becomes the signature unchanged:
// no 65th byte is cut and s is not made low-S. Last, the token must verify
// with pub, else ErrSelfCheck, which catches a signer holding another key
// and an answer that is not 64-byte r||s.
func Sign(ctx context.Context, s Signer, pub crypto.PublicKey, header Header, payload []byte) (string, error) {
	pt, err := ec.FromPublicKey(pub)
	if err != nil {
		return "", keyError("signer public key", err)
	}
	if s == nil {
		return "", fmt.Errorf("%w: nil signer", jose.ErrInvalidArgument)
	}
	if ctx == nil {
		return "", fmt.Errorf("%w: nil context", jose.ErrInvalidArgument)
	}
	alg := s.Alg()
	if !isSupportedAlg(alg) {
		return "", fmt.Errorf("%w: signer alg %s; %s", jose.ErrUnsupportedAlg, errtext.Quote(alg), supportedAlgs)
	}
	if want := algOf(pt.Kind); alg != want {
		return "", fmt.Errorf("%w: signer alg %s, key on %s needs %s", ErrAlgKeyMismatch, alg, pt.Kind.Name(), want)
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
		return "", fmt.Errorf("%w: header alg %s differs from %q, the alg of the signer", jose.ErrInvalidArgument, got, alg)
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
	// RFC 7515 §5.1 steps 2, 4 and 5: the JWS Signing Input.
	signingInput := jose.EncodeSegment(headerJSON) + "." + jose.EncodeSegment(payload)
	sig, err := s.Sign(ctx, []byte(signingInput))
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrSignerFailed, err)
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
// original payload bytes (not decoded as JSON), in this order:
//  1. an allowed entry other than ES256 and ES256K is jose.ErrUnsupportedAlg,
//     returned before compact is read, so a caller's list naming an alg the
//     SDK lacks never reads as a bad token; nil or empty allows both;
//  2. exactly three dot-separated parts, each strict base64url, the payload
//     may be empty, the header at most 64 KiB decoded and a JSON object
//     (jose.DecodeJSON rules) with a string alg, else jose.ErrMalformed; crit
//     or b64 is ErrUnsupportedHeader;
//  3. alg must be ES256 or ES256K and in allowed, else ErrAlgNotAllowed (RFC
//     7515 §5.2, RFC 8725 §3.1), so none, HS*, RS*, PS* and EdDSA never pass;
//     for an alg the SDK does not implement the text names the algs it
//     supports. An alg read from the token is never jose.ErrUnsupportedAlg;
//  4. key is an *ecdsa.PublicKey on P-256 or secp256k1, else
//     jose.ErrUnsupportedKey; nil or not on its curve is ErrBadKey; its curve
//     must match alg, else ErrAlgKeyMismatch. The key is never taken from
//     the header: jwk, x5c, jku and x5u are ignored (RFC 7515 §6, §10.3);
//  5. the signature is exactly 64 bytes (no DER, no 65-byte r||s||v), r and
//     s in [1, n-1], and verifies with SHA-256 over the received
//     header.payload string, else ErrBadSignature. Low-S and high-S both
//     verify: RFC 7518 §3.4 and RFC 8812 §3.2 put no limit on s beyond ECDSA
//     verification, which accepts any s in [1, n-1] (FIPS 186-5 §6.4.2 step
//     1).
func Verify(compact string, key crypto.PublicKey, allowed []string) (Header, []byte, error) {
	for _, a := range allowed {
		if !isSupportedAlg(a) {
			return nil, nil, fmt.Errorf("%w: allowed algs list %s; %s", jose.ErrUnsupportedAlg, errtext.Quote(a), supportedAlgs)
		}
	}
	tok, err := parse(compact)
	if err != nil {
		return nil, nil, err
	}
	header, alg, sig := tok.header, tok.header.Alg(), tok.sig

	// RFC 7515 §5.2 (last paragraph), RFC 7518 §8.5 and RFC 8725 §3.1: the
	// caller names the algorithms it accepts; only ES256 and ES256K ever are,
	// so none (RFC 7518 §3.6) is never accepted.
	if !isSupportedAlg(alg) {
		return nil, nil, fmt.Errorf("%w: %s; %s", ErrAlgNotAllowed, errtext.Quote(alg), supportedAlgs)
	}
	if len(allowed) > 0 && !slices.Contains(allowed, alg) {
		return nil, nil, fmt.Errorf("%w: %s is not in the allowed list", ErrAlgNotAllowed, errtext.Quote(alg))
	}
	pt, err := ec.FromPublicKey(key)
	if err != nil {
		return nil, nil, keyError("verification key", err)
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

// keyError puts an ec key error in the classes of jose (INV-03): an
// unsupported key type or curve stays jose.ErrUnsupportedKey, anything else
// is ErrBadKey. %v for the second, as ec's text wraps nothing.
func keyError(what string, err error) error {
	if errors.Is(err, jose.ErrUnsupportedKey) {
		return fmt.Errorf("%s: %w", what, err)
	}
	return fmt.Errorf("%w: %s: %v", ErrBadKey, what, err)
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
	// compact is exactly parts[0] "." parts[1] "." parts[2], so the signing
	// input is a prefix of it: slicing does not copy a megabyte-long token
	// once more on every parse.
	signingInput := compact[:len(parts[0])+1+len(parts[1])]
	return parsed{header: header, payload: payload, sig: sig, signingInput: signingInput}, nil
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

// supportedAlgs ends the text of every jose.ErrUnsupportedAlg of this package,
// and of the ErrAlgNotAllowed for a token alg the SDK does not implement.
const supportedAlgs = "the SDK supports ES256 and ES256K"

func isSupportedAlg(alg string) bool {
	return alg == AlgES256 || alg == AlgES256K
}
