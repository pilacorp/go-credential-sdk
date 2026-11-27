package jsonmap

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/pilacorp/go-credential-sdk/credential/common/crypto"
	"github.com/pilacorp/go-credential-sdk/credential/common/dto"
)

// A detached JWS header is read by jose's rules. With encoding/json, the last
// of two "b64" members won, so {"b64":true,"b64":false} passed as unencoded
// payload while a reader keeping the first saw an encoded one; and "KID"
// filled kid.
func TestDetachedJWSHeader_StrictJSON(t *testing.T) {
	enc := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	if _, err := detachedJWSAlg(enc(`{"alg":"ES256","b64":true,"b64":false,"crit":["b64"]}`)); err == nil || !strings.Contains(err.Error(), "duplicate key") {
		t.Errorf("duplicate b64: err = %v, want a duplicate key refused", err)
	}
	if alg, err := detachedJWSAlg(enc(`{"alg":"ES256","b64":false,"crit":["b64"]}`)); err != nil || alg != "ES256" {
		t.Errorf("valid header: %q, %v", alg, err)
	}
	if kid, ok := jwsKid(enc(`{"KID":"#k"}`) + ".."); ok {
		t.Errorf("KID read as kid %q", kid)
	}
	big := enc(`{"alg":"ES256","b64":false,"crit":["b64"],"x":"` + strings.Repeat("a", 70<<10) + `"}`)
	if _, err := detachedJWSAlg(big); err == nil || !strings.Contains(err.Error(), "header is over") {
		t.Errorf("70 KiB header: err = %v, want it refused for its size", err)
	}
}

// A JwtProof2020 with a malformed header is reported for its header, before
// its kid is compared with proof.verificationMethod.
func TestJwtProofHeaderCheckedBeforeKid(t *testing.T) {
	enc := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	tok := enc(`{"alg":"none","kid":"did:example:a#k1"}`) + "." + enc(`{}`) + ".c2ln"
	m := &JSONMap{}
	_, err := m.verifyJWTProof(nil, &dto.Proof{VerificationMethod: "did:example:a#other", Extra: map[string]interface{}{"jwt": tok}})
	if err == nil || errors.Is(err, crypto.ErrJwtProofBinding) || !strings.Contains(err.Error(), "alg") {
		t.Fatalf("err = %v, want the header's alg refused before the kid compare", err)
	}
}
