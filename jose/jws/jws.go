// Package jws signs and verifies JSON Web Signatures in the JWS Compact
// Serialization (RFC 7515 §7.1) with ES256, ECDSA P-256 SHA-256 (RFC 7518
// §3.4), and ES256K, ECDSA secp256k1 SHA-256 (RFC 8812 §3.2).
package jws

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"fmt"
	"math/big"
	"slices"
	"strings"

	"github.com/pilacorp/go-credential-sdk/jose"
	"github.com/pilacorp/go-credential-sdk/jose/internal/ec"
)

const (
	AlgES256  = "ES256"  // ECDSA P-256 with SHA-256 (RFC 7518 §3.4)
	AlgES256K = "ES256K" // ECDSA secp256k1 with SHA-256 (RFC 8812 §3.2)
)

// Signer signs a 32-byte SHA-256 digest and returns r||s (64 bytes), or, for
// secp256k1 only, r||s||v (65 bytes, go-ethereum style). The private key stays
// with the signer (in memory, Vault, HSM).
//
// Same method set as credential/common/signer.SignerProvider, so existing
// providers satisfy it without this module importing go-ethereum.
type Signer interface {
	Sign(digest []byte) ([]byte, error)
}

// KeyedSigner is a Signer that knows its public key. A Signer alone cannot
// tell Sign which curve its key is on, so a key on the wrong curve for alg
// would yield a token nobody can verify; with Public, Sign refuses the
// mismatch before signing and verifies the token before returning it.
// credential/common/signer.P256Provider satisfies it. A nil Public() means
// the key is unknown and both checks are skipped.
type KeyedSigner interface {
	Signer
	Public() *ecdsa.PublicKey
}

// Header is a decoded JOSE Header (RFC 7515 §4).
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

// Sign builds a compact JWS over payload (RFC 7515 §5.1, §7.1), signed
// through s:
//  1. alg must be ES256 or ES256K; it is written into the header, and an alg
//     the caller put in header must equal it;
//  2. the header is encoded with jose.EncodeJSON (no HTML escaping, UTF-8
//     kept);
//  3. payload is signed exactly as given, never re-encoded;
//  4. the SHA-256 digest of base64url(header) "." base64url(payload) goes to s;
//  5. a 64-byte answer is r||s; a 65-byte one is r||s||v, accepted for
//     ES256K only and the last byte is dropped; anything else (DER included)
//     is ErrSignatureFormat;
//  6. r and s must be in [1, n-1], then s is normalised to low-S on both
//     curves, so one token has one encoding;
//  7. when s is a KeyedSigner with a non-nil Public, the key must be on
//     the curve of alg (ErrAlgKeyMismatch, checked before s is called) and the
//     token must verify with it (ErrSignatureFormat).
//
// A header with crit, or with b64 other than true, is refused: Verify would
// refuse the token it produces.
func Sign(s Signer, alg string, header Header, payload []byte) (string, error) {
	kind, ok := kindForAlg(alg)
	if !ok {
		return "", fmt.Errorf("%w: %q (want ES256 or ES256K)", jose.ErrAlgNotAllowed, alg)
	}
	if s == nil {
		return "", fmt.Errorf("%w: nil signer", jose.ErrInvalidArgument)
	}
	var pub *ecdsa.PublicKey
	if ks, ok := s.(KeyedSigner); ok {
		pub = ks.Public()
	}
	if pub != nil {
		pt, err := ec.FromPublicKey(pub)
		if err != nil {
			return "", fmt.Errorf("signer public key: %w", err)
		}
		if pt.Kind != kind {
			return "", fmt.Errorf("%w: alg %q, signer key on %s", jose.ErrAlgKeyMismatch, alg, pt.Kind.Name())
		}
	}
	h := make(map[string]any, len(header)+1)
	for k, v := range header {
		h[k] = v
	}
	// RFC 7515 §5.1 step 5: alg must accurately represent the algorithm used.
	if v, ok := h["alg"]; ok && v != alg {
		return "", fmt.Errorf("%w: header alg %v differs from %q", jose.ErrInvalidArgument, v, alg)
	}
	if err := checkHeaderExtensions(h); err != nil {
		return "", err
	}
	h["alg"] = alg

	headerJSON, err := jose.EncodeJSON(h)
	if err != nil {
		return "", fmt.Errorf("header: %w", err)
	}
	// RFC 7515 §5.1 steps 2, 4 and 5: the JWS Signing Input, hashed with
	// SHA-256 (RFC 7518 §3.4, RFC 8812 §3.2 step 1).
	signingInput := jose.EncodeSegment(headerJSON) + "." + jose.EncodeSegment(payload)
	digest := sha256.Sum256([]byte(signingInput))

	raw, err := s.Sign(digest[:])
	if err != nil {
		return "", fmt.Errorf("%w: %w", jose.ErrSigner, err)
	}
	// RFC 7518 §3.4 and RFC 8812 §3.2: the signature is R||S, 32 octets each.
	switch len(raw) {
	case 64:
	case 65:
		if kind != ec.Secp256k1 {
			return "", fmt.Errorf("%w: signer returned 65-byte r||s||v under %s; a recovery id comes from a secp256k1 key", jose.ErrSignatureFormat, alg)
		}
		raw = raw[:64]
	default:
		return "", fmt.Errorf("%w: signer returned %d bytes, want 64-byte r||s (65 with a trailing recovery id)", jose.ErrSignatureFormat, len(raw))
	}
	curve := kind.Curve()
	n := curve.Params().N
	r := new(big.Int).SetBytes(raw[:32])
	sv := new(big.Int).SetBytes(raw[32:])
	// FIPS 186-5 §6.4.2 step 1 (= SEC 1 v2.0 §4.1.4 step 1): reject unless
	// 1 <= r, s <= n-1. A signer answering outside that range produced a
	// signature every verifier rejects.
	if !inScalarRange(r, n) || !inScalarRange(sv, n) {
		return "", fmt.Errorf("%w: signer returned r or s outside [1, n-1]", jose.ErrSignatureFormat)
	}
	sv = NormalizeLowS(curve, sv)

	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	sv.FillBytes(sig[32:])
	// RFC 7515 §5.1 step 8: the JWS Compact Serialization.
	token := signingInput + "." + jose.EncodeSegment(sig)
	if pub != nil {
		if _, _, err := Verify(token, pub, []string{alg}); err != nil {
			return "", fmt.Errorf("%w: signature does not verify with the signer's public key: %w", jose.ErrSignatureFormat, err)
		}
	}
	return token, nil
}

// Verify checks a compact JWS against key and returns its header and the
// original payload bytes (not decoded as JSON):
//  1. exactly three non-empty dot-separated parts, each strict base64url;
//  2. the header is a JSON object (jose.DecodeJSON rules) with a string alg;
//  3. crit, or b64 other than true, is ErrUnsupportedHeader;
//  4. the key is never taken from the header: jwk, x5c, jku and x5u are
//     ignored. RFC 7515 §6 and §10.3: the caller supplies the key from a
//     source whose origin it has authenticated;
//  5. alg must be ES256 or ES256K (none, HS*, RS*, PS*, EdDSA are refused even
//     if listed) and in allowed (nil or empty means both); the key decides the
//     algorithm, P-256 ⇒ ES256, secp256k1 ⇒ ES256K, else ErrAlgKeyMismatch;
//  6. the signature is exactly 64 bytes (no DER, no 65 bytes on this side),
//     r and s in [1, n-1], else ErrBadSignature;
//  7. SHA-256 over the received header.payload string. Low-S and high-S both
//     verify: RFC 7518 §3.4 and RFC 8812 §3.2 put no limit on s beyond ECDSA
//     verification, which accepts any s in [1, n-1] (FIPS 186-5 §6.4.2 step
//     1).
func Verify(compact string, key *ecdsa.PublicKey, allowed []string) (Header, []byte, error) {
	// RFC 7515 §5.2 step 1 and §7.1: three parts separated by exactly two
	// periods. SplitN, not Split: a megabyte of dots must not become a million
	// strings before the count is checked.
	parts := strings.SplitN(compact, ".", 4)
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return nil, nil, fmt.Errorf("%w: a compact JWS has three non-empty parts", jose.ErrMalformed)
	}
	// RFC 7515 §5.2 steps 2, 6 and 7: strict base64url, no line breaks.
	headerJSON, err := jose.DecodeSegment(parts[0])
	if err != nil {
		return nil, nil, fmt.Errorf("header: %w", err)
	}
	payload, err := jose.DecodeSegment(parts[1])
	if err != nil {
		return nil, nil, fmt.Errorf("payload: %w", err)
	}
	sig, err := jose.DecodeSegment(parts[2])
	if err != nil {
		return nil, nil, fmt.Errorf("signature: %w", err)
	}
	// RFC 7515 §5.2 steps 3 and 4: a valid JSON object without duplicate
	// Header Parameter names.
	obj, err := jose.DecodeJSONObject(headerJSON)
	if err != nil {
		return nil, nil, fmt.Errorf("header: %w", err)
	}
	header := Header(obj)
	// RFC 7515 §4.1.1: alg MUST be present; its value is a string.
	alg, ok := header["alg"].(string)
	if !ok {
		return nil, nil, fmt.Errorf("%w: header alg must be a string", jose.ErrMalformed)
	}
	if err := checkHeaderExtensions(header); err != nil {
		return nil, nil, err
	}

	// RFC 7515 §5.2 (last paragraph), RFC 7518 §8.5 and RFC 8725 §3.1: the
	// caller names the algorithms it accepts; only ES256 and ES256K ever are,
	// so none (RFC 7518 §3.6) is never accepted.
	if _, ok := kindForAlg(alg); !ok {
		return nil, nil, fmt.Errorf("%w: %q", jose.ErrAlgNotAllowed, alg)
	}
	if len(allowed) > 0 && !slices.Contains(allowed, alg) {
		return nil, nil, fmt.Errorf("%w: %q is not in the allowed list", jose.ErrAlgNotAllowed, alg)
	}
	pt, err := ec.FromPublicKey(key)
	if err != nil {
		return nil, nil, err
	}
	// RFC 7518 §3.4 and RFC 8812 §3.2, §3.3: ES256 is P-256 only and ES256K
	// is secp256k1 only, so the key decides the algorithm (RFC 8725 §3.1: one
	// algorithm per key, checked when the key is used).
	if algOf(pt.Kind) != alg {
		return nil, nil, fmt.Errorf("%w: header alg %q, key on %s", jose.ErrAlgKeyMismatch, alg, pt.Kind.Name())
	}

	// RFC 7518 §3.4 validation step 1: the signature MUST be a 64-octet
	// sequence; RFC 8812 §3.2 step 4 defines the ES256K signature as the same
	// 64-octet R||S.
	if len(sig) != 64 {
		return nil, nil, fmt.Errorf("%w: signature is %d bytes, want 64-byte r||s", jose.ErrBadSignature, len(sig))
	}
	n := pt.Kind.Curve().Params().N
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	// FIPS 186-5 §6.4.2 step 1 (= SEC 1 v2.0 §4.1.4 step 1): reject unless
	// 1 <= r, s <= n-1.
	if !inScalarRange(r, n) || !inScalarRange(s, n) {
		return nil, nil, fmt.Errorf("%w: r or s outside [1, n-1]", jose.ErrBadSignature)
	}

	// RFC 7515 §5.2 step 8, RFC 7518 §3.4 and RFC 8812 §3.2 step 1: SHA-256
	// over the received header.payload string, the JWS Signing Input.
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !pt.VerifyRS(digest[:], sig) {
		return nil, nil, fmt.Errorf("%w", jose.ErrBadSignature)
	}
	return header, payload, nil
}

// inScalarRange reports whether 1 <= v <= n-1; nil is never in range.
func inScalarRange(v, n *big.Int) bool {
	return v != nil && n != nil && v.Sign() > 0 && v.Cmp(n) < 0
}

// checkHeaderExtensions refuses the two header members that change how a JWS
// is processed. RFC 7515 §4.1.11: the recipient MUST understand every
// extension crit lists, and none is supported. RFC 7797 §3: b64 false changes
// the JWS Signing Input, which is not supported; RFC 7797 §6 requires crit
// alongside it, so a b64 without crit does not conform either.
func checkHeaderExtensions(h map[string]any) error {
	if _, ok := h["crit"]; ok {
		return fmt.Errorf("%w: crit", jose.ErrUnsupportedHeader)
	}
	if v, ok := h["b64"]; ok && v != true {
		return fmt.Errorf("%w: b64 must be absent or true", jose.ErrUnsupportedHeader)
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

func kindForAlg(alg string) (ec.Kind, bool) {
	switch alg {
	case AlgES256:
		return ec.P256, true
	case AlgES256K:
		return ec.Secp256k1, true
	}
	return 0, false
}

// NormalizeLowS returns s if s <= n/2, otherwise n-s. Both are valid ECDSA
// signatures over the same input; fixing one keeps one encoding per signed
// token, so a hash over the token (the anchoring leaf) is stable. Same rule as
// credential/common/signer.NormalizeLowS, which this module cannot import
// without pulling in go-ethereum.
//
// s must be a valid signature scalar, 1 <= s <= n-1 (check it first; Sign and
// anchor.Leaf do). A nil curve or s gives nil. The result is otherwise always
// a new big.Int, never s itself, so changing it never changes s.
func NormalizeLowS(curve elliptic.Curve, s *big.Int) *big.Int {
	if curve == nil || s == nil || curve.Params() == nil || curve.Params().N == nil {
		return nil
	}
	n := curve.Params().N
	if s.Cmp(new(big.Int).Rsh(n, 1)) > 0 {
		return new(big.Int).Sub(n, s)
	}
	return new(big.Int).Set(s)
}
