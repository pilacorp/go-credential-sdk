package sdjwt

import (
	"encoding/json"
	"testing"
)

func TestArrayDecoy(t *testing.T) {
	// Test case: add decoys to an array field (arrayContainer)
	vc := map[string]interface{}{
		"credentialSubject": map[string]interface{}{
			"name": "John",
			"emails": []interface{}{
				"john@example.com",
				"john.doe@work.com",
			},
		},
	}

	// Add 2 decoys to "emails" array
	result, err := BuildDisclosures(BuildDisclosuresInput{
		VC:             vc,
		SelectivePaths: []string{"credentialSubject.name"},
		Decoys: []DecoyConfig{
			{Path: "credentialSubject.emails", Count: 2},
		},
	})
	if err != nil {
		t.Fatalf("BuildDisclosures failed: %v", err)
	}

	// Verify decoys were added to emails array
	vcMap := result.ProcessedVC
	credSubject := vcMap["credentialSubject"].(map[string]interface{})
	emails := credSubject["emails"].([]interface{})

	t.Logf("Number of emails after decoy: %d", len(emails))
	t.Logf("Emails: %+v", emails)

	// Should have original 2 emails + 2 decoys = 4
	if len(emails) != 4 {
		t.Errorf("Expected 4 emails (2 original + 2 decoys), got %d", len(emails))
	}

	// First 2 should be strings (original emails)
	for i := 0; i < 2; i++ {
		if _, isStr := emails[i].(string); !isStr {
			t.Errorf("Expected emails[%d] to be string, got %T", i, emails[i])
		}
	}

	// Last 2 should be decoy objects with "..." key
	for i := 2; i < 4; i++ {
		decoyMap, ok := emails[i].(map[string]interface{})
		if !ok {
			t.Errorf("Expected emails[%d] to be map, got %T", i, emails[i])
			continue
		}
		if _, hasKey := decoyMap["..."]; !hasKey {
			t.Errorf("Expected decoy to have '...' key, got %+v", decoyMap)
		}
	}
}

func TestArrayDecoyWithEmptyPath(t *testing.T) {
	// Test case: add decoys to root-level _sd
	vc := map[string]interface{}{
		"credentialSubject": map[string]interface{}{
			"name": "John",
		},
	}

	// Add 3 decoys to empty path (root)
	result, err := BuildDisclosures(BuildDisclosuresInput{
		VC:             vc,
		SelectivePaths: []string{"credentialSubject.name"},
		Decoys: []DecoyConfig{
			{Path: "", Count: 3},
		},
	})
	if err != nil {
		t.Fatalf("BuildDisclosures failed: %v", err)
	}

	// Verify decoys were added at root
	vcMap := result.ProcessedVC
	rootSD, ok := vcMap["_sd"]
	if !ok {
		t.Fatal("Expected _sd array at root")
	}

	sdArr, ok := rootSD.([]interface{})
	if !ok {
		t.Fatal("_sd is not an array")
	}

	t.Logf("Root _sd length: %d", len(sdArr))
	t.Logf("Root _sd: %+v", sdArr)

	if len(sdArr) != 3 {
		t.Errorf("Expected 3 decoys at root, got %d", len(sdArr))
	}
}

func TestObjectDecoyPath(t *testing.T) {
	// Test case: add decoys to object field (credentialSubject)
	vc := map[string]interface{}{
		"credentialSubject": map[string]interface{}{
			"name":  "John",
			"age":   30,
			"email": "john@example.com",
		},
	}

	// Add 2 decoys to credentialSubject object
	result, err := BuildDisclosures(BuildDisclosuresInput{
		VC:             vc,
		SelectivePaths: []string{"credentialSubject.name"},
		Decoys: []DecoyConfig{
			{Path: "credentialSubject", Count: 2},
		},
	})
	if err != nil {
		t.Fatalf("BuildDisclosures failed: %v", err)
	}

	// Verify decoys were added to credentialSubject._sd
	vcMap := result.ProcessedVC
	credSubject := vcMap["credentialSubject"].(map[string]interface{})
	csSD, ok := credSubject["_sd"]
	if !ok {
		t.Fatal("Expected _sd array in credentialSubject")
	}

	sdArr, ok := csSD.([]interface{})
	if !ok {
		t.Fatal("_sd is not an array")
	}

	t.Logf("credentialSubject._sd length: %d", len(sdArr))
	// Should have 1 (name) + 2 (decoys) = 3
	if len(sdArr) != 3 {
		t.Errorf("Expected 3 items in _sd (1 field + 2 decoys), got %d", len(sdArr))
	}

	// Verify name is in _sd as digest
	hasNameSD := false
	for _, item := range sdArr {
		if s, ok := item.(string); ok && len(s) > 0 {
			hasNameSD = true
			break
		}
	}
	if !hasNameSD {
		t.Error("Expected name digest in _sd")
	}
}

func TestMultipleDecoys(t *testing.T) {
	// Test case: add decoys at multiple paths
	vc := map[string]interface{}{
		"credentialSubject": map[string]interface{}{
			"name":   "John",
			"age":    30,
			"emails": []interface{}{"john@example.com"},
		},
	}

	result, err := BuildDisclosures(BuildDisclosuresInput{
		VC:             vc,
		SelectivePaths: []string{"credentialSubject.name"},
		Decoys: []DecoyConfig{
			{Path: "", Count: 2},                      // 2 at root
			{Path: "credentialSubject", Count: 3},      // 3 in credentialSubject
			{Path: "credentialSubject.emails", Count: 1}, // 1 in emails array
		},
	})
	if err != nil {
		t.Fatalf("BuildDisclosures failed: %v", err)
	}

	vcMap := result.ProcessedVC

	// Check root _sd
	rootSD := vcMap["_sd"].([]interface{})
	if len(rootSD) != 2 {
		t.Errorf("Expected 2 decoys at root, got %d", len(rootSD))
	}

	// Check credentialSubject._sd
	credSubject := vcMap["credentialSubject"].(map[string]interface{})
	csSD := credSubject["_sd"].([]interface{})
	// Should have 1 (name) + 3 (decoys) = 4
	if len(csSD) != 4 {
		t.Errorf("Expected 4 items in credentialSubject._sd, got %d", len(csSD))
	}

	// Check emails array
	emails := credSubject["emails"].([]interface{})
	// Should have 1 original + 1 decoy = 2
	if len(emails) != 2 {
		t.Errorf("Expected 2 emails (1 original + 1 decoy), got %d", len(emails))
	}

	// Verify first is original string
	if _, ok := emails[0].(string); !ok {
		t.Errorf("Expected emails[0] to be string, got %T", emails[0])
	}

	// Verify second is decoy
	if decoy, ok := emails[1].(map[string]interface{}); !ok {
		t.Errorf("Expected emails[1] to be decoy map, got %T", emails[1])
	} else {
		if _, hasKey := decoy["..."]; !hasKey {
			t.Errorf("Expected decoy to have '...' key, got %+v", decoy)
		}
	}

	// Debug output
	resultJSON, _ := json.MarshalIndent(result.ProcessedVC, "", "  ")
	t.Logf("Result VC:\n%s", string(resultJSON))
}
