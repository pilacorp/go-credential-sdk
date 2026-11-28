package sdjwt

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/pilacorp/go-credential-sdk/jose"
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

	// The 2 emails keep their order; the 2 decoys are placeholders, placed at
	// random so their position tells nothing (RFC 9901 §4.2.5).
	var kept []interface{}
	for _, el := range emails {
		if m, ok := el.(map[string]interface{}); ok {
			if _, ok := m["..."]; !ok || len(m) != 1 {
				t.Errorf("element %v is not a placeholder", m)
			}
			continue
		}
		kept = append(kept, el)
	}
	if len(kept) != 2 || kept[0] != "john@example.com" || kept[1] != "john.doe@work.com" {
		t.Errorf("emails kept %v", kept)
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
			{Path: "", Count: 2},                         // 2 at root
			{Path: "credentialSubject", Count: 3},        // 3 in credentialSubject
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

	// One element is the original email, the other a placeholder.
	var placeholders int
	for _, el := range emails {
		if m, ok := el.(map[string]interface{}); ok && len(m) == 1 && m["..."] != nil {
			placeholders++
		} else if el != "john@example.com" {
			t.Errorf("unexpected element %v", el)
		}
	}
	if placeholders != 1 {
		t.Errorf("%d placeholders, want 1", placeholders)
	}

	// Debug output
	resultJSON, _ := json.MarshalIndent(result.ProcessedVC, "", "  ")
	t.Logf("Result VC:\n%s", string(resultJSON))
}

func TestNestedArrayElement(t *testing.T) {
	// Test case: selective disclosure of nested array element
	vc := map[string]interface{}{
		"credentialSubject": map[string]interface{}{
			"name": "John",
			"addresses": []interface{}{
				map[string]interface{}{"city": "NYC", "zip": "10001"},
				map[string]interface{}{"city": "LA", "zip": "90001"},
			},
		},
	}

	// Disclose only first address city
	result, err := BuildDisclosures(BuildDisclosuresInput{
		VC:             vc,
		SelectivePaths: []string{"credentialSubject.addresses[0].city"},
	})
	if err != nil {
		t.Fatalf("BuildDisclosures failed: %v", err)
	}

	// Verify first address has placeholder
	vcMap := result.ProcessedVC
	credSubject := vcMap["credentialSubject"].(map[string]interface{})
	addresses := credSubject["addresses"].([]interface{})

	firstAddr := addresses[0].(map[string]interface{})
	if _, hasPlaceholder := firstAddr["_sd"]; !hasPlaceholder {
		t.Error("Expected _sd in first address (disclosed)")
	}

	// Second address should be unchanged
	secondAddr := addresses[1].(map[string]interface{})
	if _, hasPlaceholder := secondAddr["_sd"]; hasPlaceholder {
		t.Error("Second address should not have _sd")
	}
	if city, ok := secondAddr["city"].(string); !ok || city != "LA" {
		t.Errorf("Second address city should be 'LA', got %v", secondAddr["city"])
	}

	t.Logf("Disclosures: %v", result.Disclosures)
}

func TestSelectiveWithDecoys(t *testing.T) {
	// Test case: selective disclosure + decoys together
	vc := map[string]interface{}{
		"credentialSubject": map[string]interface{}{
			"name":  "John",
			"email": "john@example.com",
			"phone": "1234567890",
		},
	}

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

	vcMap := result.ProcessedVC
	credSubject := vcMap["credentialSubject"].(map[string]interface{})
	csSD := credSubject["_sd"].([]interface{})

	// Should have 1 (name) + 2 (decoys) = 3
	if len(csSD) != 3 {
		t.Errorf("Expected 3 items in _sd, got %d", len(csSD))
	}

	// Verify name is disclosed (should NOT be in _sd, should have disclosure)
	if _, hasName := credSubject["name"]; hasName {
		t.Error("name should be replaced by digest")
	}

	// Verify other fields are still present (not disclosed)
	if email, ok := credSubject["email"].(string); !ok || email != "john@example.com" {
		t.Errorf("email should be present, got %v", credSubject["email"])
	}

	t.Logf("Disclosures count: %d", len(result.Disclosures))
}

func TestEmptyDisclosures(t *testing.T) {
	// Test case: empty selective paths (should return original VC)
	vc := map[string]interface{}{
		"credentialSubject": map[string]interface{}{
			"name": "John",
			"age":  30,
		},
	}

	result, err := BuildDisclosures(BuildDisclosuresInput{
		VC:             vc,
		SelectivePaths: []string{},
	})
	if err != nil {
		t.Fatalf("BuildDisclosures failed: %v", err)
	}

	// Should return original VC unchanged
	credSubject := result.ProcessedVC["credentialSubject"].(map[string]interface{})
	if name, ok := credSubject["name"].(string); !ok || name != "John" {
		t.Errorf("name should be 'John', got %v", credSubject["name"])
	}
	// Just check name is preserved
	_ = credSubject["age"]
	if _, hasSD := credSubject["_sd"]; hasSD {
		t.Error("Should not have _sd when no selective paths")
	}
}

// Test BuildDisclosures with empty SelectivePaths but with Decoys
// Bug: disclosure.go:70-72 - no _sd_alg when only decoys
func TestBuildDisclosures_EmptySelectivePathsWithDecoys(t *testing.T) {
	vc := map[string]interface{}{
		"credentialSubject": map[string]interface{}{
			"name": "John",
		},
	}

	result, err := BuildDisclosures(BuildDisclosuresInput{
		VC:             vc,
		SelectivePaths: []string{}, // empty
		Decoys: []DecoyConfig{
			{Path: "credentialSubject", Count: 2},
		},
	})
	if err != nil {
		t.Fatalf("BuildDisclosures failed: %v", err)
	}

	// Should have _sd with decoys
	cs := result.ProcessedVC["credentialSubject"].(map[string]interface{})
	if _, hasSD := cs["_sd"]; !hasSD {
		t.Error("should have _sd with decoys")
	}

	// No disclosures should be generated
	if len(result.Disclosures) != 0 {
		t.Errorf("expected no disclosures, got %d", len(result.Disclosures))
	}
}

// Decoys name containers the way the claims read as JSON, whatever Go type
// holds them, and prebuilt digests in the VC survive new paths (README,
// advanced path): both reach Reconstruct with every disclosure.
func TestBuildDisclosures_TypedContainersAndPrebuiltDigests(t *testing.T) {
	first, err := BuildDisclosures(BuildDisclosuresInput{
		VC:             map[string]interface{}{"credentialSubject": map[string]interface{}{"bloodType": "O", "name": "x"}},
		SelectivePaths: []string{"credentialSubject.bloodType"},
	})
	if err != nil {
		t.Fatal(err)
	}
	cs := first.ProcessedVC["credentialSubject"].(map[string]interface{})
	cs["tags"] = []string{"a", "b"}
	second, err := BuildDisclosures(BuildDisclosuresInput{
		VC:             first.ProcessedVC,
		SelectivePaths: []string{"credentialSubject.name"},
		Decoys:         []DecoyConfig{{Path: "credentialSubject.tags", Count: 2}},
	})
	if err != nil {
		t.Fatal(err)
	}
	cs = second.ProcessedVC["credentialSubject"].(map[string]interface{})
	sd := cs["_sd"].([]interface{})
	if len(sd) != 2 {
		t.Errorf("credentialSubject._sd has %d digests, want bloodType + name", len(sd))
	}
	// The prebuilt digest and the new one are merged into one sorted _sd
	// (RFC 9901 §4.2.4.1).
	if len(sd) == 2 && sd[0].(string) > sd[1].(string) {
		t.Errorf("credentialSubject._sd = %v, want it sorted", sd)
	}

	if n := len(cs["tags"].([]interface{})); n != 4 {
		t.Errorf("tags has %d elements, want 2 + 2 decoys", n)
	}
	out, err := Reconstruct(second.ProcessedVC, append(first.Disclosures, second.Disclosures...), true)
	if err != nil {
		t.Fatal(err)
	}
	got := out["credentialSubject"].(map[string]interface{})
	if got["bloodType"] != "O" || got["name"] != "x" || len(got["tags"].([]interface{})) != 2 {
		t.Errorf("reconstructed %v", got)
	}
}

// An issuer's integer past 2^53 keeps its digits in the payload it signs.
func TestBuildDisclosures_KeepsLargeIntegers(t *testing.T) {
	res, err := BuildDisclosures(BuildDisclosuresInput{
		VC:             map[string]interface{}{"credentialSubject": map[string]interface{}{"n": int64(9007199254740993), "name": "x"}},
		SelectivePaths: []string{"credentialSubject.name"},
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(res.ProcessedVC["credentialSubject"].(map[string]interface{})["n"])
	if err != nil || string(b) != "9007199254740993" {
		t.Fatalf("n = %s, %v; want 9007199254740993", b, err)
	}
}

// Prebuilt sha-256 digests with a sha-384 build would match no disclosure:
// refused at build, not at verify.
func TestBuildDisclosures_PrebuiltDigestOfAnotherHashRefused(t *testing.T) {
	first, err := BuildDisclosures(BuildDisclosuresInput{
		VC:             map[string]interface{}{"credentialSubject": map[string]interface{}{"a": "1", "b": "2"}},
		SelectivePaths: []string{"credentialSubject.a"},
	})
	if err != nil {
		t.Fatal(err)
	}
	delete(first.ProcessedVC, "_sd_alg") // as when only credentialSubject is carried over
	_, err = BuildDisclosures(BuildDisclosuresInput{
		VC:             first.ProcessedVC,
		SelectivePaths: []string{"credentialSubject.b"},
		HashAlgorithm:  AlgSHA384,
	})
	if err == nil || !strings.Contains(err.Error(), "made with another hash") {
		t.Fatalf("err = %v, want the sha-256 digest refused under sha-384", err)
	}
}

// A decoy path that is not in the VC is refused; it used to be skipped, which
// hid the caller's mistake and left the array or object unpadded.
func TestBuildDisclosures_MissingDecoyPathRefused(t *testing.T) {
	_, err := BuildDisclosures(BuildDisclosuresInput{
		VC:     map[string]interface{}{"credentialSubject": map[string]interface{}{"name": "x"}},
		Decoys: []DecoyConfig{{Path: "credentialSubject.nope", Count: 2}},
	})
	if !errors.Is(err, jose.ErrInvalidArgument) || !strings.Contains(err.Error(), "not in the credential") {
		t.Fatalf("err = %v, want the missing decoy path refused as a caller mistake", err)
	}
}

// Paths in errors are written in the dot notation callers use: services
// return this text to whoever sent the paths.
func TestBuildDisclosures_ErrorsNamePathsInDotNotation(t *testing.T) {
	vc := func() map[string]interface{} {
		return map[string]interface{}{"credentialSubject": map[string]interface{}{"a": 1, "tags": []interface{}{"x"}}}
	}
	for _, tc := range []struct {
		in   BuildDisclosuresInput
		want string
	}{
		{BuildDisclosuresInput{VC: vc(), SelectivePaths: []string{"credentialSubject.tags[3]"}}, `"credentialSubject.tags[3]"`},
		{BuildDisclosuresInput{VC: vc(), SelectivePaths: []string{"credentialSubject.a", "credentialSubject.a"}}, `"credentialSubject.a"`},
		{BuildDisclosuresInput{VC: vc(), Decoys: []DecoyConfig{{Path: "credentialSubject.a", Count: 1001}}}, `"credentialSubject"`},
		{BuildDisclosuresInput{VC: vc(), Decoys: []DecoyConfig{{Path: "", Count: 1001}}}, `at ""`},
		{BuildDisclosuresInput{VC: vc(), SelectivePaths: []string{"credentialSubject.tags[3]", "[3]"}}, `"credentialSubject.tags[3]" does`},
		{BuildDisclosuresInput{VC: map[string]interface{}{"credentialSubject": map[string]interface{}{"a": 1, "x": map[string]interface{}{"...": 1}}},
			SelectivePaths: []string{"credentialSubject.a"}}, `at "credentialSubject.x"`},
	} {
		_, err := BuildDisclosures(tc.in)
		if !errors.Is(err, jose.ErrInvalidArgument) || !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), `["`) || strings.Contains(err.Error(), `[]`) {
			t.Errorf("err = %v, want %s named in dot notation", err, tc.want)
		}
	}
}

// With nothing to conceal, every plain vc+jwt passes through BuildDisclosures:
// the VC comes back with the caller's Go types, as before this package ran
// on jose.
func TestBuildDisclosures_NothingToConcealKeepsGoTypes(t *testing.T) {
	res, err := BuildDisclosures(BuildDisclosuresInput{
		VC: map[string]interface{}{"credentialSubject": map[string]interface{}{"age": 30, "tags": []string{"a"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	cs := res.ProcessedVC["credentialSubject"].(map[string]interface{})
	if _, ok := cs["age"].(int); !ok {
		t.Errorf("age is %T, want int", cs["age"])
	}
	if _, ok := cs["tags"].([]string); !ok {
		t.Errorf("tags is %T, want []string", cs["tags"])
	}
}

// A parent and a child path conceal together (RFC 9901 §4.2.6), in the dot
// and [index] syntax, and the disclosures come deeper paths first.
func TestBuildDisclosures_ParentAndChildPaths(t *testing.T) {
	vc := map[string]interface{}{"credentialSubject": map[string]interface{}{
		"address": map[string]interface{}{"city": "x"},
		"tags":    []interface{}{"a", "b"},
	}}
	res, err := BuildDisclosures(BuildDisclosuresInput{
		VC:             vc,
		SelectivePaths: []string{"credentialSubject.address", "credentialSubject.address.city", "credentialSubject.tags[1]"},
	})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeDisclosures(res.Disclosures)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 3 || decoded[0].FieldName != "city" {
		t.Fatalf("disclosures %+v, want city (the deepest) first", decoded)
	}
	out, err := Reconstruct(res.ProcessedVC, res.Disclosures, true)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(out, vc) {
		t.Fatalf("reconstructed %v, want %v", out, vc)
	}
}

// Decoys aimed at one target through different paths (a claim's path adds to
// the object holding it) add up.
func TestBuildDisclosures_DecoysAtOneTargetAddUp(t *testing.T) {
	res, err := BuildDisclosures(BuildDisclosuresInput{
		VC:     map[string]interface{}{"credentialSubject": map[string]interface{}{"name": "x", "age": 1}},
		Decoys: []DecoyConfig{{Path: "credentialSubject.name", Count: 2}, {Path: "credentialSubject.age", Count: 3}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if n := len(res.ProcessedVC["credentialSubject"].(map[string]interface{})["_sd"].([]interface{})); n != 5 {
		t.Fatalf("credentialSubject._sd has %d decoys, want 2 + 3", n)
	}
}

// A VC whose top-level _sd_alg names another hash than HashAlgorithm is
// refused: its prebuilt digests could match no disclosure.
func TestBuildDisclosures_PrebuiltSDAlgMismatchRefused(t *testing.T) {
	_, err := BuildDisclosures(BuildDisclosuresInput{
		VC:             map[string]interface{}{"_sd_alg": AlgSHA512, "credentialSubject": map[string]interface{}{"a": "1"}},
		SelectivePaths: []string{"credentialSubject.a"},
	})
	if !errors.Is(err, jose.ErrInvalidArgument) || !strings.Contains(err.Error(), "_sd_alg") {
		t.Fatalf("err = %v, want the _sd_alg mismatch refused", err)
	}
}

// A selective path may not name a placeholder a caller built earlier: its
// disclosure is not here to conceal again.
func TestBuildDisclosures_PathToPrebuiltPlaceholderRefused(t *testing.T) {
	_, err := BuildDisclosures(BuildDisclosuresInput{
		VC: map[string]interface{}{"credentialSubject": map[string]interface{}{
			"tags": []interface{}{map[string]interface{}{"...": "X9yH0Ajrdm1Oij4tWso9UzzKJvPoDxwmuEcO3XAdRC0"}, "b"}}},
		SelectivePaths: []string{"credentialSubject.tags[0]"},
	})
	if !errors.Is(err, jose.ErrInvalidArgument) || !strings.Contains(err.Error(), "prebuilt placeholder") {
		t.Fatalf("err = %v, want the path to a prebuilt placeholder refused", err)
	}
}

// A decoy entry with Count 0 is skipped, path unchecked, as before.
func TestBuildDisclosures_ZeroCountDecoySkipped(t *testing.T) {
	if _, err := BuildDisclosures(BuildDisclosuresInput{
		VC:             map[string]interface{}{"credentialSubject": map[string]interface{}{"a": 1}},
		SelectivePaths: []string{"credentialSubject.a"},
		Decoys:         []DecoyConfig{{Path: "credentialSubject.nope", Count: 0}},
	}); err != nil {
		t.Fatalf("err = %v, want a Count 0 decoy skipped", err)
	}
}
