package sdjwt

import (
	"strings"
	"testing"
)

func TestParsePath(t *testing.T) {
	segs, err := parsePath("credentialSubject.emails[1].city")
	if err != nil {
		t.Fatalf("parsePath failed: %v", err)
	}
	if len(segs) != 3 {
		t.Fatalf("expected 3 segments, got %d", len(segs))
	}
	if segs[0].key != "credentialSubject" || segs[0].index != nil {
		t.Fatalf("unexpected first segment: %+v", segs[0])
	}
	if segs[1].key != "emails" || segs[1].index == nil || *segs[1].index != 1 {
		t.Fatalf("unexpected second segment: %+v", segs[1])
	}
	if segs[2].key != "city" || segs[2].index != nil {
		t.Fatalf("unexpected third segment: %+v", segs[2])
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

func TestResolvePath_ArrayElementMetadata(t *testing.T) {
	vc := map[string]interface{}{
		"credentialSubject": map[string]interface{}{
			"emails": []interface{}{"a@example.com", "b@example.com"},
		},
	}

	resolved, err := resolvePath(vc, "credentialSubject.emails[1]")
	if err != nil {
		t.Fatalf("resolvePath failed: %v", err)
	}
	if resolved == nil {
		t.Fatal("resolvePath returned nil target")
	}
	if resolved.kind != TargetKindArrayElem {
		t.Fatalf("expected TargetKindArrayElem, got %s", resolved.kind.String())
	}
	if resolved.parentKey != "emails" {
		t.Fatalf("expected parentKey emails, got %q", resolved.parentKey)
	}
	if resolved.parentMap == nil {
		t.Fatal("expected non-nil parentMap")
	}
	if _, ok := (*resolved.parentMap)["emails"]; !ok {
		t.Fatalf("parentMap does not contain emails key: %#v", *resolved.parentMap)
	}
}

func TestResolvePath_ArrayIndexOutOfRange(t *testing.T) {
	vc := map[string]interface{}{
		"credentialSubject": map[string]interface{}{
			"emails": []interface{}{"a@example.com"},
		},
	}

	_, err := resolvePath(vc, "credentialSubject.emails[2]")
	if err == nil {
		t.Fatal("expected index out of range error")
	}
	if !strings.Contains(err.Error(), "out of range") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolvePath_SegmentTypeMismatch(t *testing.T) {
	vc := map[string]interface{}{
		"credentialSubject": map[string]interface{}{
			"emails": "not-an-array",
		},
	}

	_, err := resolvePath(vc, "credentialSubject.emails[0]")
	if err == nil {
		t.Fatal("expected type mismatch error")
	}
	if !strings.Contains(err.Error(), "expects array") {
		t.Fatalf("unexpected error: %v", err)
	}
}
