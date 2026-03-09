package verificationmethod

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewStaticResolver_EmptyKey(t *testing.T) {
	resolver, err := NewStaticResolver("")
	assert.Error(t, err)
	assert.Nil(t, resolver)
	assert.Contains(t, err.Error(), "public key is empty")
}

func TestStaticResolver_GetPublicKey(t *testing.T) {
	const key = "0xabcdef"

	resolver, err := NewStaticResolver(key)
	assert.NoError(t, err)
	assert.NotNil(t, resolver)

	got, err := resolver.GetPublicKey("did:example:123#key-1")
	assert.NoError(t, err)
	assert.Equal(t, key, got)
}

