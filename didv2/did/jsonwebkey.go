package did

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
)

// jsonWebKeyVMType is the verification method type VC-JOSE-COSE requires when a
// key comes from a DID document: the key sits in publicKeyJwk, and the method's
// type is JsonWebKey. The CID v1 context defines both terms.
const jsonWebKeyVMType = "JsonWebKey"

// JWK curve names a JsonWebKey method may carry.
const (
	jwkCurveSecp256k1 = "secp256k1"
	jwkCurveP256      = "P-256"
)

// coordinateLen is the byte length of an x or y coordinate on both curves.
const coordinateLen = 32

// NewSecp256k1JsonWebKeyVM builds a JsonWebKey verification method holding a
// secp256k1 key, from a "#name" fragment and the key as hex (compressed or
// uncompressed, with or without "0x"). It is the same key a secp256k1 method
// publishes as publicKeyHex, written as the JWK VC JOSE needs.
func NewSecp256k1JsonWebKeyVM(did, fragment, publicKeyHex string) (VerificationMethod, error) {
	raw, err := hex.DecodeString(strings.TrimPrefix(strings.ToLower(publicKeyHex), "0x"))
	if err != nil {
		return VerificationMethod{}, fmt.Errorf("NewSecp256k1JsonWebKeyVM: decode public key hex: %w", err)
	}

	var pub *ecdsa.PublicKey
	switch len(raw) {
	case 33:
		pub, err = crypto.DecompressPubkey(raw)
	case 65:
		pub, err = crypto.UnmarshalPubkey(raw)
	default:
		return VerificationMethod{}, fmt.Errorf("NewSecp256k1JsonWebKeyVM: public key is %d bytes, want 33 or 65", len(raw))
	}
	if err != nil {
		return VerificationMethod{}, fmt.Errorf("NewSecp256k1JsonWebKeyVM: invalid secp256k1 public key: %w", err)
	}

	// RFC 7518 6.2.1.2: each coordinate is the full field length, so a
	// coordinate with leading zero bytes keeps them.
	x := pub.X.FillBytes(make([]byte, coordinateLen))
	y := pub.Y.FillBytes(make([]byte, coordinateLen))

	return VerificationMethod{
		Id:         canonicalVMID(did, fragment),
		Type:       jsonWebKeyVMType,
		Controller: did,
		PublicKeyJwk: map[string]any{
			"kty": "EC",
			"crv": jwkCurveSecp256k1,
			"x":   base64.RawURLEncoding.EncodeToString(x),
			"y":   base64.RawURLEncoding.EncodeToString(y),
		},
	}, nil
}

// publicJWKPoint checks that jwk is a public EC key of the shape a JsonWebKey
// method may publish, and returns its curve and its point, uncompressed
// (0x04 || x || y).
//
// The shape is exact: kty, crv, x and y, nothing else. A "d" would publish the
// private key. kid, alg or use are not needed by any reader and would make the
// document rebuilt from the chain record differ from the one hashed.
func publicJWKPoint(jwk map[string]any) (crv string, point []byte, err error) {
	if _, ok := jwk["d"]; ok {
		return "", nil, fmt.Errorf("publicKeyJwk must not carry a private key")
	}
	if len(jwk) != 4 {
		return "", nil, fmt.Errorf("publicKeyJwk must have exactly kty, crv, x, y")
	}

	members := make(map[string]string, 4)
	for _, name := range []string{"kty", "crv", "x", "y"} {
		v, ok := jwk[name]
		if !ok {
			return "", nil, fmt.Errorf("publicKeyJwk must have exactly kty, crv, x, y")
		}
		s, ok := v.(string)
		if !ok {
			return "", nil, fmt.Errorf("publicKeyJwk %s must be a string", name)
		}
		members[name] = s
	}

	if members["kty"] != "EC" {
		return "", nil, fmt.Errorf("publicKeyJwk kty %q is not supported: want EC", members["kty"])
	}

	crv = members["crv"]
	if crv != jwkCurveSecp256k1 && crv != jwkCurveP256 {
		return "", nil, fmt.Errorf("publicKeyJwk crv %q is not supported: want %s or %s", crv, jwkCurveSecp256k1, jwkCurveP256)
	}

	point = make([]byte, 0, 1+2*coordinateLen)
	point = append(point, 0x04)
	for _, name := range []string{"x", "y"} {
		c, err := decodeCoordinate(members[name])
		if err != nil {
			return "", nil, fmt.Errorf("publicKeyJwk %s: %w", name, err)
		}
		point = append(point, c...)
	}

	if !onCurve(crv, point) {
		return "", nil, fmt.Errorf("publicKeyJwk point is not on curve %s", crv)
	}

	return crv, point, nil
}

// decodeCoordinate reads an unpadded base64url coordinate of exactly 32 bytes.
// Strict rejects non-zero trailing bits, so each coordinate has one encoding.
func decodeCoordinate(s string) ([]byte, error) {
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("not unpadded base64url: %w", err)
	}
	if len(b) != coordinateLen {
		return nil, fmt.Errorf("%d bytes, want %d", len(b), coordinateLen)
	}

	return b, nil
}

func onCurve(crv string, uncompressed []byte) bool {
	switch crv {
	case jwkCurveSecp256k1:
		_, err := crypto.UnmarshalPubkey(uncompressed)
		return err == nil
	case jwkCurveP256:
		_, err := ecdh.P256().NewPublicKey(uncompressed)
		return err == nil
	default:
		return false
	}
}

// compressPoint turns an uncompressed point (0x04 || x || y) into its 33-byte
// compressed form; both curves use the same SEC 1 encoding.
func compressPoint(uncompressed []byte) []byte {
	x, y := uncompressed[1:1+coordinateLen], uncompressed[1+coordinateLen:]
	prefix := byte(0x02)
	if y[len(y)-1]&1 == 1 {
		prefix = 0x03
	}

	return append([]byte{prefix}, x...)
}
