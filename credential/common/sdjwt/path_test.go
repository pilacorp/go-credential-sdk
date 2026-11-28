package sdjwt

import (
	"reflect"
	"strings"
	"testing"

	josesdjwt "github.com/pilacorp/go-credential-sdk/jose/sdjwt"
)

func TestParsePath(t *testing.T) {
	got, err := parsePath("credentialSubject.emails[1].city")
	if err != nil {
		t.Fatalf("parsePath failed: %v", err)
	}
	want := josesdjwt.Path{"credentialSubject", "emails", 1, "city"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parsePath = %v, want %v", got, want)
	}
}

func TestParsePath_InvalidCases(t *testing.T) {
	tests := []struct {
		path    string
		wantErr string
	}{
		{path: "emails[", wantErr: "invalid array segment"},
		{path: "emails[]", wantErr: "empty index"},
		{path: "emails[*]", wantErr: "wildcard index"},
		{path: "emails[abc]", wantErr: "invalid index"},
		{path: "emails[-1]", wantErr: "invalid index"},
	}

	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			_, err := parsePath(tc.path)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}
