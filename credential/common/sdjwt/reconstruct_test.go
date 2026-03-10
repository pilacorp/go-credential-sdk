package sdjwt

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func hashAndParseDisclosureForTest(t *testing.T, sdAlg string, arr []interface{}) (string, disclosureInfo) {
	t.Helper()
	disc := encodeDisclosureForTest(t, arr)
	h, err := hashDisclosure(sdAlg, disc)
	if err != nil {
		t.Fatalf("hashDisclosure failed: %v", err)
	}
	info, err := parseDisclosure(disc)
	if err != nil {
		t.Fatalf("parseDisclosure failed: %v", err)
	}
	return h, info
}

func TestValidateAndGetAlgorithm(t *testing.T) {
	tests := []struct {
		name        string
		vc          map[string]interface{}
		validateAlg bool
		wantAlg     string
		wantErr     string
	}{
		{name: "default-algorithm", vc: map[string]interface{}{}, validateAlg: true, wantAlg: DefaultHashAlgorithm},
		{name: "custom-supported", vc: map[string]interface{}{"_sd_alg": AlgSHA512}, validateAlg: true, wantAlg: AlgSHA512},
		{name: "unsupported-validated", vc: map[string]interface{}{"_sd_alg": "sha-999"}, validateAlg: true, wantErr: "unsupported _sd_alg"},
		{name: "unsupported-not-validated", vc: map[string]interface{}{"_sd_alg": "sha-999"}, validateAlg: false, wantAlg: "sha-999"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := validateAndGetAlgorithm(tc.vc, tc.validateAlg)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("validateAndGetAlgorithm failed: %v", err)
			}
			if got != tc.wantAlg {
				t.Fatalf("algorithm = %q, want %q", got, tc.wantAlg)
			}
		})
	}
}

func TestBuildDisclosureMap_SkipEmptyAndParse(t *testing.T) {
	valid := encodeDisclosureForTest(t, []interface{}{"salt", "name", "Alice"})
	m, err := buildDisclosureMap([]string{"", valid}, AlgSHA256)
	if err != nil {
		t.Fatalf("buildDisclosureMap failed: %v", err)
	}
	if len(m) != 1 {
		t.Fatalf("expected one disclosure hash, got %d", len(m))
	}
}

func TestBuildDisclosureMap_InvalidDisclosure(t *testing.T) {
	_, err := buildDisclosureMap([]string{"bad@@@"}, AlgSHA256)
	if err == nil {
		t.Fatal("expected parse error for invalid disclosure")
	}
	if !strings.Contains(err.Error(), "failed to decode disclosure") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestProcessNode_ObjectContextRejectArrayDisclosure(t *testing.T) {
	h, info := hashAndParseDisclosureForTest(t, AlgSHA256, []interface{}{"salt-x", "array-value"})
	disclosureMap := map[string]disclosureInfo{h: info}

	node := map[string]interface{}{
		"_sd": []interface{}{h},
	}

	_, err := processNode(node, disclosureMap)
	if err == nil {
		t.Fatal("expected context mismatch error")
	}
	if !strings.Contains(err.Error(), "array element disclosure used in object context") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestProcessNode_ArrayContextRejectObjectDisclosure(t *testing.T) {
	h, info := hashAndParseDisclosureForTest(t, AlgSHA256, []interface{}{"salt-x", "name", "Alice"})
	disclosureMap := map[string]disclosureInfo{h: info}

	node := []interface{}{
		map[string]interface{}{"...": h},
	}

	_, err := processNode(node, disclosureMap)
	if err == nil {
		t.Fatal("expected context mismatch error")
	}
	if !strings.Contains(err.Error(), "object field disclosure used in array context") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestProcessNode_DuplicateFieldAfterReconstruct(t *testing.T) {
	h, info := hashAndParseDisclosureForTest(t, AlgSHA256, []interface{}{"salt-x", "name", "Alice"})
	disclosureMap := map[string]disclosureInfo{h: info}

	node := map[string]interface{}{
		"name": "already-exists",
		"_sd":  []interface{}{h},
	}

	_, err := processNode(node, disclosureMap)
	if err == nil {
		t.Fatal("expected duplicate field error")
	}
	if !strings.Contains(err.Error(), "duplicate field") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestReconstruct_ArrayPlaceholder(t *testing.T) {
	arr := []interface{}{"salt123", "Item1"}
	b, err := json.Marshal(arr)
	require.NoError(t, err)
	D := base64.RawURLEncoding.EncodeToString(b)

	h, err := hashDisclosure(AlgSHA256, D)
	require.NoError(t, err)

	vc := map[string]interface{}{
		"items": []interface{}{
			map[string]interface{}{"...": h},
		},
	}

	out, err := Reconstruct(vc, []string{D}, true)
	require.NoError(t, err)

	itemsRaw, ok := out["items"]
	require.True(t, ok)

	items, ok := itemsRaw.([]interface{})
	require.True(t, ok)
	require.Len(t, items, 1)
	assert.Equal(t, "Item1", items[0])
}

func TestReconstruct_RealExampleFromCompact(t *testing.T) {
	compact := "eyJ0eXAiOiJzZCtqd3QiLCJhbGciOiJFUzI1NiJ9.eyJpZCI6IjEyMzQiLCJfc2QiOlsiYkRUUnZtNS1Zbi1IRzdjcXBWUjVPVlJJWHNTYUJrNTdKZ2lPcV9qMVZJNCIsImV0M1VmUnlsd1ZyZlhkUEt6Zzc5aGNqRDFJdHpvUTlvQm9YUkd0TW9zRmsiLCJ6V2ZaTlMxOUF0YlJTVGJvN3NKUm4wQlpRdldSZGNob0M3VVphYkZyalk4Il0sIl9zZF9hbGciOiJzaGEtMjU2In0.n27NCtnuwytlBYtUNjgkesDP_7gN7bhaLhWNL4SWT6MaHsOjZ2ZMp987GgQRL6ZkLbJ7Cd3hlePHS84GBXPuvg~WyI1ZWI4Yzg2MjM0MDJjZjJlIiwiZmlyc3RuYW1lIiwiSm9obiJd~WyJjNWMzMWY2ZWYzNTg4MWJjIiwibGFzdG5hbWUiLCJEb2UiXQ~WyJmYTlkYTUzZWJjOTk3OThlIiwic3NuIiwiMTIzLTQ1LTY3ODkiXQ~eyJ0eXAiOiJrYitqd3QiLCJhbGciOiJFUzI1NiJ9.eyJpYXQiOjE3MTAwNjk3MjIsImF1ZCI6ImRpZDpleGFtcGxlOjEyMyIsIm5vbmNlIjoiazh2ZGYwbmQ2Iiwic2RfaGFzaCI6Il8tTmJWSzNmczl3VzNHaDNOUktSNEt1NmZDMUwzN0R2MFFfalBXd0ppRkUifQ.pqw2OB5IA5ya9Mxf60hE3nr2gsJEIoIlnuCa4qIisijHbwg3WzTDFmW2SuNvK_ORN0WU6RoGbJx5uYZh8k4EbA"

	parsed, err := Parse(compact)
	require.NoError(t, err)

	parts := strings.Split(parsed.BaseJWT, ".")
	require.Len(t, parts, 3)

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)

	var payload map[string]interface{}
	err = json.Unmarshal(payloadBytes, &payload)
	require.NoError(t, err)

	out, err := Reconstruct(payload, parsed.Disclosures, true)
	require.NoError(t, err)

	assert.Equal(t, "1234", out["id"])
	assert.Equal(t, "John", out["firstname"])
	assert.Equal(t, "Doe", out["lastname"])
	assert.Equal(t, "123-45-6789", out["ssn"])

	_, hasSd := out["_sd"]
	assert.False(t, hasSd)
	_, hasAlg := out["_sd_alg"]
	assert.False(t, hasAlg)
}

func TestValidation_DuplicateDigestInArray(t *testing.T) {
	arr1 := []interface{}{"salt1", "value1"}
	b1, _ := json.Marshal(arr1)
	D1 := base64.RawURLEncoding.EncodeToString(b1)

	h1, _ := hashDisclosure(AlgSHA256, D1)

	vcWithDup := map[string]interface{}{
		"items": []interface{}{
			map[string]interface{}{"...": h1},
			map[string]interface{}{"...": h1},
		},
	}

	_, err := Reconstruct(vcWithDup, []string{D1}, true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate digest")
}

func TestBuildDisclosuresAndReconstruct_ObjectField(t *testing.T) {
	original := map[string]interface{}{
		"name": "Alice",
		"age":  float64(30),
	}

	result, err := BuildDisclosures(BuildDisclosuresInput{
		VC:             original,
		SelectivePaths: []string{"name"},
	})
	require.NoError(t, err)

	processed := result.ProcessedVC

	_, hasName := processed["name"]
	assert.False(t, hasName)
	assert.Equal(t, float64(30), processed["age"])

	assert.Equal(t, AlgSHA256, processed["_sd_alg"])
	rawSD, ok := processed["_sd"]
	require.True(t, ok)

	switch v := rawSD.(type) {
	case []string:
		assert.Len(t, v, 1)
	case []interface{}:
		assert.Len(t, v, 1)
	default:
		t.Fatalf("unexpected type for _sd: %T", rawSD)
	}

	require.Len(t, result.Disclosures, 1)

	reconstructed, err := Reconstruct(processed, result.Disclosures, true)
	require.NoError(t, err)

	assert.Equal(t, "Alice", reconstructed["name"])
	assert.Equal(t, float64(30), reconstructed["age"])
	_, hasSd := reconstructed["_sd"]
	assert.False(t, hasSd)
	_, hasAlg := reconstructed["_sd_alg"]
	assert.False(t, hasAlg)
}

func TestBuildDisclosuresAndReconstruct_ArrayElementPath(t *testing.T) {
	original := map[string]interface{}{
		"tags": []interface{}{"public", "email", "phone"},
		"note": "test",
	}

	result, err := BuildDisclosures(BuildDisclosuresInput{
		VC:             original,
		SelectivePaths: []string{"tags[1]"},
	})
	require.NoError(t, err)

	processed := result.ProcessedVC
	assert.Equal(t, AlgSHA256, processed["_sd_alg"])

	rawTags, ok := processed["tags"]
	require.True(t, ok)

	tags, ok := rawTags.([]interface{})
	require.True(t, ok)
	require.Len(t, tags, 3)

	placeholder, ok := tags[1].(map[string]interface{})
	require.True(t, ok)
	require.Len(t, placeholder, 1)
	_, hasDots := placeholder["..."]
	assert.True(t, hasDots, "expected placeholder {...: h} at tags[1]")

	require.Len(t, result.Disclosures, 1)

	out, err := Reconstruct(processed, result.Disclosures, true)
	require.NoError(t, err)

	outTags, ok := out["tags"].([]interface{})
	require.True(t, ok)
	require.Len(t, outTags, 3)
	assert.Equal(t, "public", outTags[0])
	assert.Equal(t, "email", outTags[1])
	assert.Equal(t, "phone", outTags[2])

	_, hasSd := out["_sd"]
	assert.False(t, hasSd)
	_, hasAlg := out["_sd_alg"]
	assert.False(t, hasAlg)
}

func TestBuildDisclosuresAndReconstruct_RecursiveObjectPath(t *testing.T) {
	original := map[string]interface{}{
		"id": "1234",
		"person": map[string]interface{}{
			"profile": map[string]interface{}{
				"name": "Alice",
				"age":  float64(30),
			},
		},
	}

	result, err := BuildDisclosures(BuildDisclosuresInput{
		VC:             original,
		SelectivePaths: []string{"person.profile.name"},
	})
	require.NoError(t, err)

	processed := result.ProcessedVC

	assert.Equal(t, AlgSHA256, processed["_sd_alg"])
	_, hasRootSd := processed["_sd"]
	assert.False(t, hasRootSd)

	rawPerson, ok := processed["person"].(map[string]interface{})
	require.True(t, ok)

	rawProfile, ok := rawPerson["profile"].(map[string]interface{})
	require.True(t, ok)

	_, hasName := rawProfile["name"]
	assert.False(t, hasName)
	assert.Equal(t, float64(30), rawProfile["age"])

	rawSd, ok := rawProfile["_sd"]
	require.True(t, ok)
	switch v := rawSd.(type) {
	case []string:
		assert.Len(t, v, 1)
	case []interface{}:
		assert.Len(t, v, 1)
	default:
		t.Fatalf("unexpected type for profile._sd: %T", rawSd)
	}

	require.Len(t, result.Disclosures, 1)

	out, err := Reconstruct(processed, result.Disclosures, true)
	require.NoError(t, err)

	outPerson, ok := out["person"].(map[string]interface{})
	require.True(t, ok)

	outProfile, ok := outPerson["profile"].(map[string]interface{})
	require.True(t, ok)

	assert.Equal(t, "Alice", outProfile["name"])
	assert.Equal(t, float64(30), outProfile["age"])

	_, hasSdProfile := outProfile["_sd"]
	assert.False(t, hasSdProfile)
	_, hasAlg := out["_sd_alg"]
	assert.False(t, hasAlg)
}

func TestBuildDisclosures_RecursiveParentAndChildPaths(t *testing.T) {
	original1 := map[string]interface{}{
		"id": "1234",
		"person": map[string]interface{}{
			"profile": map[string]interface{}{
				"name": "Alice",
				"age":  float64(30),
			},
		},
	}
	_, err := BuildDisclosures(BuildDisclosuresInput{
		VC:             original1,
		SelectivePaths: []string{"person.profile", "person.profile.name"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `path "person.profile.name" not found`)

	original2 := map[string]interface{}{
		"id": "1234",
		"person": map[string]interface{}{
			"profile": map[string]interface{}{
				"name": "Alice",
				"age":  float64(30),
			},
		},
	}
	result, err := BuildDisclosures(BuildDisclosuresInput{
		VC:             original2,
		SelectivePaths: []string{"person.profile.name", "person.profile"},
	})
	require.NoError(t, err)
	require.Len(t, result.Disclosures, 2)

	out, err := Reconstruct(result.ProcessedVC, result.Disclosures, true)
	require.NoError(t, err)

	assert.Equal(t, "1234", out["id"])

	outPerson, ok := out["person"].(map[string]interface{})
	require.True(t, ok)

	outProfile, ok := outPerson["profile"].(map[string]interface{})
	require.True(t, ok)

	assert.Equal(t, "Alice", outProfile["name"])
	assert.Equal(t, float64(30), outProfile["age"])

	_, hasSdProfile := outProfile["_sd"]
	assert.False(t, hasSdProfile)
	_, hasAlg := out["_sd_alg"]
	assert.False(t, hasAlg)
}

func TestBuildDisclosures_ArrayParentAndChildPaths(t *testing.T) {
	original1 := map[string]interface{}{
		"tags": []interface{}{"public", "email", "phone"},
		"note": "test",
	}
	_, err := BuildDisclosures(BuildDisclosuresInput{
		VC:             original1,
		SelectivePaths: []string{"tags", "tags[1]"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `path "tags[1]" not found`)

	original2 := map[string]interface{}{
		"tags": []interface{}{"public", "email", "phone"},
		"note": "test",
	}
	result, err := BuildDisclosures(BuildDisclosuresInput{
		VC:             original2,
		SelectivePaths: []string{"tags[1]", "tags"},
	})
	require.NoError(t, err)
	require.Len(t, result.Disclosures, 2)

	out, err := Reconstruct(result.ProcessedVC, result.Disclosures, true)
	require.NoError(t, err)

	outTags, ok := out["tags"].([]interface{})
	require.True(t, ok)
	require.Len(t, outTags, 3)
	assert.Equal(t, "public", outTags[0])
	assert.Equal(t, "email", outTags[1])
	assert.Equal(t, "phone", outTags[2])

	assert.Equal(t, "test", out["note"])

	_, hasSd := out["_sd"]
	assert.False(t, hasSd)
	_, hasAlg := out["_sd_alg"]
	assert.False(t, hasAlg)
}

func TestBuildDisclosures_WithOptions(t *testing.T) {
	original := map[string]interface{}{
		"name": "Alice",
		"age":  float64(30),
		"city": "NYC",
	}

	result, err := BuildDisclosures(BuildDisclosuresInput{
		VC:             original,
		SelectivePaths: []string{"name", "age"},
		HashAlgorithm:  AlgSHA384,
	})
	require.NoError(t, err)
	assert.Equal(t, AlgSHA384, result.ProcessedVC["_sd_alg"])

	out, err := Reconstruct(result.ProcessedVC, result.Disclosures, true)
	require.NoError(t, err)
	assert.Equal(t, "Alice", out["name"])
	assert.Equal(t, float64(30), out["age"])

	_, err = BuildDisclosures(BuildDisclosuresInput{
		VC:             original,
		SelectivePaths: []string{"name", "age"},
		Shuffle:        true,
	})
	require.NoError(t, err)

	result3, err := BuildDisclosures(BuildDisclosuresInput{
		VC:             original,
		SelectivePaths: []string{"name"},
		Decoys:         []DecoyConfig{{Path: "", Count: 2}},
	})
	require.NoError(t, err)

	sd := result3.ProcessedVC["_sd"]
	switch v := sd.(type) {
	case []interface{}:
		assert.Len(t, v, 3)
	case []string:
		assert.Len(t, v, 3)
	}

	assert.Len(t, result3.Disclosures, 1)

	out3, err := Reconstruct(result3.ProcessedVC, result3.Disclosures, true)
	require.NoError(t, err)
	assert.Equal(t, "Alice", out3["name"])
}
