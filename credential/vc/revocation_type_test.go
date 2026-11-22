package vc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pilacorp/go-credential-sdk/credential/common/util"
)

// TC-B02: a credentialStatus with an unknown type is ignored by
// checkRevocation. The old code required statusListCredential, failing with
// "credentialStatus.statusListCredential is required".
func TestCheckRevocation_UnknownTypeSingleObject(t *testing.T) {
	c := CredentialData{
		"credentialStatus": map[string]interface{}{
			"type": "UnknownStatusType",
			"id":   "https://example.org/status/1",
		},
	}
	if err := checkRevocation(c); err != nil {
		t.Fatalf("checkRevocation = %v, want nil (unknown type ignored)", err)
	}
}

// TC-B01: an array with one known and one unknown type. The unknown entry is
// skipped; the known entry is checked normally. We verify that the unknown
// entry does not cause "must be an object" and that the known entry's
// revocation check succeeds.
func TestCheckRevocation_ArrayWithUnknownType(t *testing.T) {
	srv := notRevokedStatusListServer(t)
	defer srv.Close()

	c := CredentialData{
		"credentialStatus": []interface{}{
			map[string]interface{}{
				"type": "UnknownStatusType",
				"id":   "https://example.org/status/x",
			},
			map[string]interface{}{
				"type":                 "BitstringStatusListEntry",
				"id":                   srv.URL + "/status/0#1",
				"statusListCredential": srv.URL,
				"statusListIndex":      "1",
				"statusPurpose":        "revocation",
			},
		},
	}
	if err := checkRevocation(c); err != nil {
		t.Fatalf("checkRevocation (known + unknown) = %v, want nil", err)
	}
}

// notRevokedStatusListServer returns an httptest server that serves a status
// list with no bits set (nothing revoked). Same shape as the one in
// sdjwt_integrity_test.go, but with all bits clear.
func notRevokedStatusListServer(t *testing.T) *httptest.Server {
	t.Helper()
	bits := make([]byte, 16) // all zero — nothing revoked
	encoded, err := util.CompressToBase64URL(bits)
	if err != nil {
		t.Fatalf("compress status list: %v", err)
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"credentialSubject": map[string]interface{}{
					"statusPurpose": "revocation",
					"encodedList":   encoded,
				},
			},
		}); err != nil {
			t.Errorf("encode status list: %v", err)
		}
	}))
}

// The old code rejected an array outright: "credentialStatus must be an object".
func TestCheckRevocation_ArrayAccepted(t *testing.T) {
	c := CredentialData{
		"credentialStatus": []interface{}{
			map[string]interface{}{
				"type": "SomeUnknown",
				"id":   "https://example.org/status/1",
			},
			map[string]interface{}{
				"type": "AnotherUnknown",
				"id":   "https://example.org/status/2",
			},
		},
	}
	if err := checkRevocation(c); err != nil {
		t.Fatalf("checkRevocation = %v, want nil (all unknown)", err)
	}
}

// An empty array should return success.
func TestCheckRevocation_EmptyArray(t *testing.T) {
	c := CredentialData{
		"credentialStatus": []interface{}{},
	}
	if err := checkRevocation(c); err != nil {
		t.Fatalf("checkRevocation = %v, want nil (empty array)", err)
	}
}
