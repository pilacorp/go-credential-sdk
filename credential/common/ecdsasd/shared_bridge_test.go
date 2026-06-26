package ecdsasd

import (
	"encoding/hex"
	"testing"
)

func TestSharedBridge_CanonicalizeAndGroupCompatibility(t *testing.T) {
	cred := w3cCred(t)
	keys := w3cLoadKeys(t)

	hmacKey, err := hex.DecodeString(keys.HMACKeyString)
	if err != nil {
		t.Fatalf("decode hmac key: %v", err)
	}

	grouped, err := canonicalizeAndGroup(cred, hmacKey, map[string][]string{"mandatory": {"/issuer"}})
	if err != nil {
		t.Fatalf("canonicalizeAndGroup: %v", err)
	}

	if grouped == nil {
		t.Fatal("grouped result is nil")
	}
	if len(grouped.hmacNQuads) == 0 {
		t.Fatal("grouped.hmacNQuads is empty")
	}

	mandatory := grouped.groups["mandatory"]
	if mandatory == nil {
		t.Fatal(`group "mandatory" missing`)
	}

	if len(mandatory.matching) == 0 {
		t.Fatal("mandatory.matching is empty")
	}
	if len(mandatory.nonMatching) == 0 {
		t.Fatal("mandatory.nonMatching is empty")
	}
}
