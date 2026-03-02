package vc

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

// fakeResolver implements verificationmethod.ResolverProvider for testing.
type fakeResolver struct {
	called bool
}

func (f *fakeResolver) GetPublicKey(verificationMethodURL string) (string, error) {
	f.called = true
	return "", fmt.Errorf("fake resolver error")
}

func TestGetOptions_Defaults(t *testing.T) {
	opts := getOptions()

	assert.False(t, opts.isValidateSchema)
	assert.False(t, opts.isVerifyProof)
	assert.False(t, opts.isCheckExpiration)
	assert.False(t, opts.isCheckRevocation)
	assert.Equal(t, config.BaseURL, opts.didBaseURL)
	assert.Equal(t, "key-1", opts.verificationMethodKey)
	assert.Nil(t, opts.loadedSchemaLoader)
	assert.NotNil(t, opts.resolver, "default resolver should not be nil")
}

func TestGetOptions_WithBaseURLAndVerificationMethodKey(t *testing.T) {
	opts := getOptions(
		WithBaseURL("https://custom.example/did"),
		WithVerificationMethodKey("key-custom"),
	)

	assert.Equal(t, "https://custom.example/did", opts.didBaseURL)
	assert.Equal(t, "key-custom", opts.verificationMethodKey)
}

func TestGetOptions_WithResolverOverridesDefault(t *testing.T) {
	fr := &fakeResolver{}

	opts := getOptions(WithResolver(fr))
	assert.Equal(t, fr, opts.resolver, "custom resolver should override default resolver")
}
