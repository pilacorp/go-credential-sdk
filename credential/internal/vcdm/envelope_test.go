package vcdm

import "testing"

func TestCutEnvelopedDataURL(t *testing.T) {
	for _, tc := range []struct {
		name      string
		id        string
		wantOK    bool
		wantMedia string
		wantToken string
	}{
		{
			name:      "vc+jwt",
			id:        "data:application/vc+jwt,eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ0ZXN0In0.c2ln",
			wantOK:    true,
			wantMedia: MediaTypeVCJWT,
			wantToken: "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ0ZXN0In0.c2ln",
		},
		{
			name:      "vc+sd-jwt",
			id:        "data:application/vc+sd-jwt,eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ0ZXN0In0.c2ln~disc1~",
			wantOK:    true,
			wantMedia: MediaTypeVCSDJWT,
			wantToken: "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ0ZXN0In0.c2ln~disc1~",
		},
		{
			name:      "mixed case prefix",
			id:        "DATA:Application/VC+JWT,eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ0ZXN0In0.c2ln",
			wantOK:    true,
			wantMedia: MediaTypeVCJWT,
			wantToken: "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ0ZXN0In0.c2ln",
		},
		{
			name:      "empty token",
			id:        "data:application/vc+jwt,",
			wantOK:    true,
			wantMedia: MediaTypeVCJWT,
			wantToken: "",
		},
		{
			name:   "other media type",
			id:     "data:application/jwt,eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ0ZXN0In0.c2ln",
			wantOK: false,
		},
		{
			name:   "no comma",
			id:     "data:application/vc+jwt",
			wantOK: false,
		},
		{
			name:   "plain URL",
			id:     "https://example.com/vc/1",
			wantOK: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mediaType, token, ok := CutEnvelopedDataURL(tc.id)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if mediaType != tc.wantMedia {
				t.Fatalf("mediaType = %q, want %q", mediaType, tc.wantMedia)
			}
			if token != tc.wantToken {
				t.Fatalf("token = %q, want %q", token, tc.wantToken)
			}
		})
	}
}

// A COSE_Sign1 token is binary, so its envelope is a base64 data: URL.
func TestCutEnvelopedDataURL_COSE(t *testing.T) {
	for _, id := range []string{"data:application/vc+cose;base64,AAEC", "DATA:Application/VC+COSE;BASE64,AAEC"} {
		mt, token, ok := CutEnvelopedDataURL(id)
		if !ok || mt != MediaTypeVCCOSE || token != "AAEC" {
			t.Fatalf("CutEnvelopedDataURL(%q) = %q, %q, %v", id, mt, token, ok)
		}
	}
	if _, _, ok := CutEnvelopedDataURL("data:application/vc+cose,AAEC"); ok {
		t.Fatal("a vc+cose data: URL without ;base64 was accepted")
	}
}
