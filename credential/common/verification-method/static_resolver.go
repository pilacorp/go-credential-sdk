package verificationmethod

import "fmt"

// StaticResolver is a ResolverProvider that always returns a
// preconfigured public key, without performing DID resolution.
type StaticResolver struct {
	publicKey string
}

// NewStaticResolver creates a StaticResolver that serves a fixed public key.
func NewStaticResolver(publicKey string) (*StaticResolver, error) {
	if publicKey == "" {
		return nil, fmt.Errorf("public key is empty")
	}

	return &StaticResolver{
		publicKey: publicKey,
	}, nil
}

// GetPublicKey implements ResolverProvider by returning the configured key.
// The input verificationMethodURL is ignored.
func (p *StaticResolver) GetPublicKey(_ string) (string, error) {
	return p.publicKey, nil
}
