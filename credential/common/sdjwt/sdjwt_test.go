package sdjwt

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsSDJWT(t *testing.T) {
	jwt := "aaa.bbb.ccc"
	sd := jwt + "~D1~D2~"

	assert.False(t, IsSDJWT(""), "empty string is not SD-JWT")
	assert.False(t, IsSDJWT(jwt), "plain JWT is not SD-JWT")
	assert.True(t, IsSDJWT(sd), "JWT with disclosures and '~' should be SD-JWT")
	assert.False(t, IsSDJWT("not-a-jwt~something~"), "invalid JWT prefix should not be SD-JWT")
}

func TestParseSDJWT(t *testing.T) {
	jwt := "aaa.bbb.ccc"
	// Create valid base64url disclosures: [salt, fieldName, value]
	arr1 := []interface{}{"salt1", "name", "Alice"}
	arr2 := []interface{}{"salt2", "age", float64(30)}
	b1, _ := json.Marshal(arr1)
	b2, _ := json.Marshal(arr2)
	d1 := base64.RawURLEncoding.EncodeToString(b1)
	d2 := base64.RawURLEncoding.EncodeToString(b2)

	sd := jwt + "~" + d1 + "~" + d2 + "~"

	parsed, err := Parse(sd)
	require.NoError(t, err)
	assert.Equal(t, jwt, parsed.BaseJWT)
	assert.Equal(t, []string{d1, d2}, parsed.Disclosures)
	assert.Len(t, parsed.DecodedDisclosures, 2)
}

func TestCreatePresentation(t *testing.T) {
	issuerJWT := "header.payload.sig"
	all := []string{"D1", "D2", "D3"}

	full := BuildSDJWTPresentation(issuerJWT, all)
	assert.Equal(t, "header.payload.sig~D1~D2~D3~", full)

	subset := BuildSDJWTPresentation(issuerJWT, []string{all[0], all[2]})
	assert.Equal(t, "header.payload.sig~D1~D3~", subset)

	none := BuildSDJWTPresentation(issuerJWT, nil)
	assert.Equal(t, "header.payload.sig~", none)

	empty := BuildSDJWTPresentation(issuerJWT, []string{"", "D1", ""})
	assert.Equal(t, "header.payload.sig~D1~", empty)
}

func TestPresentation(t *testing.T) {
	// Create valid base64url disclosures
	arr1 := []interface{}{"salt1", "firstname", "John"}
	arr2 := []interface{}{"salt2", "lastname", "Doe"}
	b1, _ := json.Marshal(arr1)
	b2, _ := json.Marshal(arr2)
	d1 := base64.RawURLEncoding.EncodeToString(b1)
	d2 := base64.RawURLEncoding.EncodeToString(b2)

	sd := "aaa.bbb.ccc~" + d1 + "~" + d2 + "~"
	parsed, err := Parse(sd)
	require.NoError(t, err)

	assert.Equal(t, "aaa.bbb.ccc", parsed.BaseJWT)
	assert.Equal(t, []string{d1, d2}, parsed.Disclosures)

	out := BuildSDJWTPresentation(parsed.BaseJWT, []string{d1})
	assert.Equal(t, "aaa.bbb.ccc~"+d1+"~", out)
}

func TestBuildDisclosuresAndReconstruct_ObjectField(t *testing.T) {
	original := map[string]interface{}{
		"name": "Alice",
		"age":  float64(30),
	}

	result, err := BuildDisclosures(original, []string{"name"}, "", false, nil, nil)
	require.NoError(t, err)

	processed := result.ProcessedVC

	// Processed should hide "name" and keep "age"
	_, hasName := processed["name"]
	assert.False(t, hasName)
	assert.Equal(t, float64(30), processed["age"])

	// SD-JWT metadata
	assert.Equal(t, "sha-256", processed["_sd_alg"])
	rawSD, ok := processed["_sd"]
	require.True(t, ok)

	// _sd is a slice of digests
	switch v := rawSD.(type) {
	case []string:
		assert.Len(t, v, 1)
	case []interface{}:
		assert.Len(t, v, 1)
	default:
		t.Fatalf("unexpected type for _sd: %T", rawSD)
	}

	require.Len(t, result.Disclosures, 1)

	// Reconstruct should restore the original payload and remove SD-JWT internals
	reconstructed, err := Reconstruct(processed, result.Disclosures, nil)
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

	result, err := BuildDisclosures(original, []string{"tags[1]"}, "", false, nil, nil)
	require.NoError(t, err)

	processed := result.ProcessedVC

	// root still keeps sd algorithm metadata
	assert.Equal(t, "sha-256", processed["_sd_alg"])

	// tags[1] has been replaced by placeholder { "...": h }
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

	// Reconstruct should restore "email" at index 1 and drop SD-JWT metadata
	out, err := Reconstruct(processed, result.Disclosures, nil)
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

	result, err := BuildDisclosures(original, []string{"person.profile.name"}, "", false, nil, nil)
	require.NoError(t, err)

	processed := result.ProcessedVC

	// root only has _sd_alg, no _sd
	assert.Equal(t, "sha-256", processed["_sd_alg"])
	_, hasRootSd := processed["_sd"]
	assert.False(t, hasRootSd)

	// Drill down into person.profile
	rawPerson, ok := processed["person"].(map[string]interface{})
	require.True(t, ok)

	rawProfile, ok := rawPerson["profile"].(map[string]interface{})
	require.True(t, ok)

	// name is hidden, age is still present
	_, hasName := rawProfile["name"]
	assert.False(t, hasName)
	assert.Equal(t, float64(30), rawProfile["age"])

	// profile._sd contains exactly one digest
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

	// Reconstruct should restore name, keep age, and remove sd metadata at all levels
	out, err := Reconstruct(processed, result.Disclosures, nil)
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
	// Selecting parent first and then child should fail because the child path
	// no longer exists after the parent has been replaced by SD-JWT metadata.
	original1 := map[string]interface{}{
		"id": "1234",
		"person": map[string]interface{}{
			"profile": map[string]interface{}{
				"name": "Alice",
				"age":  float64(30),
			},
		},
	}
	_, err := BuildDisclosures(original1, []string{"person.profile", "person.profile.name"}, "", false, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `path "person.profile.name" not found`)

	// Selecting child first and then parent should succeed and be reconstructable.
	original2 := map[string]interface{}{
		"id": "1234",
		"person": map[string]interface{}{
			"profile": map[string]interface{}{
				"name": "Alice",
				"age":  float64(30),
			},
		},
	}
	result, err := BuildDisclosures(original2, []string{"person.profile.name", "person.profile"}, "", false, nil, nil)
	require.NoError(t, err)
	require.Len(t, result.Disclosures, 2)

	out, err := Reconstruct(result.ProcessedVC, result.Disclosures, nil)
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
	// Selecting parent array first and then a child element should fail because
	// the array has been removed from the root after the first selection.
	original1 := map[string]interface{}{
		"tags": []interface{}{"public", "email", "phone"},
		"note": "test",
	}
	_, err := BuildDisclosures(original1, []string{"tags", "tags[1]"}, "", false, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `path "tags[1]" not found`)

	// Selecting a child element first and then the parent array should succeed.
	original2 := map[string]interface{}{
		"tags": []interface{}{"public", "email", "phone"},
		"note": "test",
	}
	result, err := BuildDisclosures(original2, []string{"tags[1]", "tags"}, "", false, nil, nil)
	require.NoError(t, err)
	require.Len(t, result.Disclosures, 2)

	out, err := Reconstruct(result.ProcessedVC, result.Disclosures, nil)
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

func TestReconstruct_ArrayPlaceholder(t *testing.T) {
	// Build a disclosure [salt, value] for array element
	arr := []interface{}{"salt123", "Item1"}
	b, err := json.Marshal(arr)
	require.NoError(t, err)
	D := base64.RawURLEncoding.EncodeToString(b)

	h, err := hashDisclosure("sha-256", D)
	require.NoError(t, err)

	vc := map[string]interface{}{
		"items": []interface{}{
			map[string]interface{}{"...": h},
		},
	}

	out, err := Reconstruct(vc, []string{D}, nil)
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

	// Decode issuer-signed JWT payload
	parts := strings.Split(parsed.BaseJWT, ".")
	require.Len(t, parts, 3)

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)

	var payload map[string]interface{}
	err = json.Unmarshal(payloadBytes, &payload)
	require.NoError(t, err)

	// Reconstruct processed payload from payload + disclosures
	out, err := Reconstruct(payload, parsed.Disclosures, nil)
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

func TestBuildDisclosures_WithOptions(t *testing.T) {
	original := map[string]interface{}{
		"name": "Alice",
		"age":  float64(30),
		"city": "NYC",
	}

	// Test with SHA-384 algorithm
	result, err := BuildDisclosures(original, []string{"name", "age"}, "sha-384", false, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, "sha-384", result.ProcessedVC["_sd_alg"])

	// Verify reconstruction works with sha-384
	out, err := Reconstruct(result.ProcessedVC, result.Disclosures, nil)
	require.NoError(t, err)
	assert.Equal(t, "Alice", out["name"])
	assert.Equal(t, float64(30), out["age"])

	// Test with shuffle
	_, err = BuildDisclosures(original, []string{"name", "age"}, "", true, nil, nil)
	require.NoError(t, err)

	// Test with decoy digests at root path
	result3, err := BuildDisclosures(original, []string{"name"}, "", false, []string{""}, []int{2})
	require.NoError(t, err)
	// Should have 1 real digest + 2 decoys = 3 total
	sd := result3.ProcessedVC["_sd"]
	switch v := sd.(type) {
	case []interface{}:
		assert.Len(t, v, 3) // 1 real + 2 decoys
	case []string:
		assert.Len(t, v, 3)
	}

	// Reconstruction should still work with decoys (they're just ignored)
	config := &ValidationConfig{
		AllowUnreferencedDisclosures: true,
	}
	out3, err := Reconstruct(result3.ProcessedVC, result3.Disclosures, config)
	require.NoError(t, err)
	assert.Equal(t, "Alice", out3["name"])
}

func TestBuildDisclosures_DisclosureInfo(t *testing.T) {
	original := map[string]interface{}{
		"name": "Alice",
		"age":  float64(30),
		"tags": []interface{}{"a", "b", "c"},
	}

	result, err := BuildDisclosures(original, []string{"name", "tags[1]"}, "", false, nil, nil)
	require.NoError(t, err)

	// Check DisclosureInfos
	require.Len(t, result.DisclosureInfos, 2)

	// First disclosure should be for "name"
	info0 := result.DisclosureInfos[0]
	assert.Equal(t, "name", info0.FieldName)
	assert.Equal(t, "name", info0.Path)
	assert.Equal(t, "Alice", info0.Value)
	assert.False(t, info0.IsDecoy)

	// Second disclosure should be for "tags[1]"
	info1 := result.DisclosureInfos[1]
	assert.Equal(t, "tags[1]", info1.Path)
	assert.Equal(t, "b", info1.Value)
	assert.False(t, info1.IsDecoy)
}

func TestValidation_DuplicateDigest(t *testing.T) {
	original := map[string]interface{}{
		"name": "Alice",
	}

	result, err := BuildDisclosures(original, []string{"name"}, "", false, nil, nil)
	require.NoError(t, err)

	// Duplicate the disclosure by adding the same string again
	discs := append(result.Disclosures, result.Disclosures[0])

	_, err = Reconstruct(result.ProcessedVC, discs, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate digest")
}

func TestValidation_UnreferencedDisclosure(t *testing.T) {
	original := map[string]interface{}{
		"name": "Alice",
		"age":  float64(30),
	}

	result, err := BuildDisclosures(original, []string{"name"}, "", false, nil, nil)
	require.NoError(t, err)

	// Create a valid disclosure for a field that doesn't exist in _sd
	// This simulates an extra disclosure that isn't referenced
	extraArr := []interface{}{"extrarandomsalt", "nonexistent", "value"}
	extraJSON, _ := json.Marshal(extraArr)
	extraDisc := base64.RawURLEncoding.EncodeToString(extraJSON)

	// Add the extra disclosure
	discs := append(result.Disclosures, extraDisc)

	// Should fail with default config (AllowUnreferencedDisclosures = false)
	_, err = Reconstruct(result.ProcessedVC, discs, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unreferenced disclosure")

	// Should pass with AllowUnreferencedDisclosures = true
	config := &ValidationConfig{
		AllowUnreferencedDisclosures: true,
	}
	out, err := Reconstruct(result.ProcessedVC, discs, config)
	require.NoError(t, err)
	assert.Equal(t, "Alice", out["name"])
}
