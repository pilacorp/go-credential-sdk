// Package jose signs and verifies compact JWS (RFC 7515) with ES256 (P-256)
// and ES256K (secp256k1), and converts EC public keys to and from JWK. See
// README.md for the rules it reads tokens with.
package jose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"fmt"
	"math/big"
	"slices"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	decredecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// Signer signs a 32-byte SHA-256 digest and returns r||s (64 bytes), or
// r||s||v (65 bytes, go-ethereum style). The private key stays with the
// signer (in memory, Vault, HSM).
//
// Same method set as credential/common/signer.SignerProvider, so existing
// providers satisfy it without this module importing go-ethereum.
type Signer interface {
	Sign(digest []byte) ([]byte, error)
}

// Header is a decoded JWS header.
type Header map[string]any

// Alg returns the alg member, or "" when absent or not a string.
func (h Header) Alg() string { return h.str("alg") }

// Typ returns the typ member, or "" when absent or not a string.
func (h Header) Typ() string { return h.str("typ") }

// Kid returns the kid member, or "" when absent or not a string.
func (h Header) Kid() string { return h.str("kid") }

func (h Header) str(name string) string {
	s, _ := h[name].(string)
	return s
}

// Sign builds a compact JWS over payload, signed through s:
//  1. alg must be ES256 or ES256K; it is written into the header, and an alg
//     the caller put in header must equal it;
//  2. the header is encoded with EncodeJSON (no HTML escaping, UTF-8 kept);
//  3. payload is signed exactly as given, never re-encoded;
//  4. the SHA-256 digest of base64url(header) "." base64url(payload) goes to s;
//  5. a 64-byte answer is r||s; a 65-byte one is r||s||v and the last byte is
//     dropped; anything else (DER included) is ErrSignatureFormat;
//  6. r and s must be in [1, n-1], then s is normalised to low-S on both
//     curves, so one token has one encoding.
//
// A header with crit, or with b64 other than true, is refused: Verify would
// refuse the token it produces.
func Sign(s Signer, alg string, header Header, payload []byte) (string, error) {
	kind, ok := kindForAlg(alg)
	if !ok {
		return "", fmt.Errorf("%w: %q (want ES256 or ES256K)", ErrAlgNotAllowed, alg)
	}
	if s == nil {
		return "", fmt.Errorf("%w: nil signer", ErrInvalidArgument)
	}
	h := make(map[string]any, len(header)+1)
	for k, v := range header {
		h[k] = v
	}
	if v, ok := h["alg"]; ok && v != alg {
		return "", fmt.Errorf("%w: header alg %v differs from %q", ErrInvalidArgument, v, alg)
	}
	if err := checkHeaderExtensions(h); err != nil {
		return "", err
	}
	h["alg"] = alg

	headerJSON, err := EncodeJSON(h)
	if err != nil {
		return "", fmt.Errorf("header: %w", err)
	}
	signingInput := EncodeSegment(headerJSON) + "." + EncodeSegment(payload)
	digest := sha256.Sum256([]byte(signingInput))

	raw, err := s.Sign(digest[:])
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrSigner, err)
	}
	switch len(raw) {
	case 64:
	case 65:
		raw = raw[:64]
	default:
		return "", fmt.Errorf("%w: signer returned %d bytes, want 64-byte r||s (65 with a trailing recovery id)", ErrSignatureFormat, len(raw))
	}
	curve := kind.curve()
	n := curve.Params().N
	r := new(big.Int).SetBytes(raw[:32])
	sv := new(big.Int).SetBytes(raw[32:])
	if !inScalarRange(r, n) || !inScalarRange(sv, n) {
		return "", fmt.Errorf("%w: signer returned r or s outside [1, n-1]", ErrSignatureFormat)
	}
	sv = NormalizeLowS(curve, sv)

	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	sv.FillBytes(sig[32:])
	return signingInput + "." + EncodeSegment(sig), nil
}

// Verify checks a compact JWS against key and returns its header and the
// original payload bytes (not decoded as JSON):
//  1. exactly three non-empty dot-separated parts, each strict base64url;
//  2. the header is a JSON object (DecodeJSON rules) with a string alg;
//  3. crit, or b64 other than true, is ErrUnsupportedHeader;
//  4. the key is never taken from the header: jwk, x5c, jku and x5u are
//     ignored;
//  5. alg must be ES256 or ES256K (none, HS*, RS*, PS*, EdDSA are refused even
//     if listed) and in allowed (nil or empty means both); the key decides the
//     algorithm, P-256 ⇒ ES256, secp256k1 ⇒ ES256K, else ErrAlgKeyMismatch;
//  6. the signature is exactly 64 bytes (no DER, no 65 bytes on this side),
//     r and s in [1, n-1], else ErrBadSignature;
//  7. SHA-256 over the received header.payload string. Low-S and high-S both
//     verify.
func Verify(compact string, key *ecdsa.PublicKey, allowed []string) (Header, []byte, error) {
	// SplitN, not Split: a megabyte of dots must not become a million strings
	// before the count is checked.
	parts := strings.SplitN(compact, ".", 4)
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return nil, nil, fmt.Errorf("%w: a compact JWS has three non-empty parts", ErrMalformed)
	}
	headerJSON, err := DecodeSegment(parts[0])
	if err != nil {
		return nil, nil, fmt.Errorf("header: %w", err)
	}
	payload, err := DecodeSegment(parts[1])
	if err != nil {
		return nil, nil, fmt.Errorf("payload: %w", err)
	}
	sig, err := DecodeSegment(parts[2])
	if err != nil {
		return nil, nil, fmt.Errorf("signature: %w", err)
	}
	obj, err := DecodeJSONObject(headerJSON)
	if err != nil {
		return nil, nil, fmt.Errorf("header: %w", err)
	}
	header := Header(obj)
	alg, ok := header["alg"].(string)
	if !ok {
		return nil, nil, fmt.Errorf("%w: header alg must be a string", ErrMalformed)
	}
	if err := checkHeaderExtensions(header); err != nil {
		return nil, nil, err
	}

	if _, ok := kindForAlg(alg); !ok {
		return nil, nil, fmt.Errorf("%w: %q", ErrAlgNotAllowed, alg)
	}
	if len(allowed) > 0 && !slices.Contains(allowed, alg) {
		return nil, nil, fmt.Errorf("%w: %q is not in the allowed list", ErrAlgNotAllowed, alg)
	}
	kind, x, y, err := coordinates(key)
	if err != nil {
		return nil, nil, err
	}
	if kind.alg() != alg {
		return nil, nil, fmt.Errorf("%w: header alg %q, key on %s", ErrAlgKeyMismatch, alg, kind.crv())
	}

	if len(sig) != 64 {
		return nil, nil, fmt.Errorf("%w: signature is %d bytes, want 64-byte r||s", ErrBadSignature, len(sig))
	}
	n := kind.curve().Params().N
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !inScalarRange(r, n) || !inScalarRange(s, n) {
		return nil, nil, fmt.Errorf("%w: r or s outside [1, n-1]", ErrBadSignature)
	}

	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	var valid bool
	if kind == curveP256 {
		pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x[:]), Y: new(big.Int).SetBytes(y[:])}
		valid = ecdsa.Verify(pub, digest[:], r, s)
	} else {
		valid = verifySecp256k1(digest[:], sig, x, y)
	}
	if !valid {
		return nil, nil, fmt.Errorf("%w", ErrBadSignature)
	}
	return header, payload, nil
}

func verifySecp256k1(digest, sig []byte, x, y [32]byte) bool {
	var fx, fy secp256k1.FieldVal
	fx.SetBytes(&x)
	fy.SetBytes(&y)
	var r, s secp256k1.ModNScalar
	r.SetByteSlice(sig[:32])
	s.SetByteSlice(sig[32:])
	return decredecdsa.NewSignature(&r, &s).Verify(digest, secp256k1.NewPublicKey(&fx, &fy))
}

// checkHeaderExtensions refuses the two header members that change how a JWS
// is processed: crit (the verifier must understand the listed extensions, and
// none is supported) and b64 (RFC 7797 unencoded payload).
func checkHeaderExtensions(h map[string]any) error {
	if _, ok := h["crit"]; ok {
		return fmt.Errorf("%w: crit", ErrUnsupportedHeader)
	}
	if v, ok := h["b64"]; ok && v != true {
		return fmt.Errorf("%w: b64 must be absent or true", ErrUnsupportedHeader)
	}
	return nil
}
