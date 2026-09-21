package didv2

import (
	"testing"

	"github.com/pilacorp/go-credential-sdk/didv2/did"
)

// WithDIDConfig copies field by field: a field missing there is dropped silently on
// the GenerateDIDTX path.
func TestWithDIDConfig_CarriesExtraVMs(t *testing.T) {
	src := &DIDConfig{
		Method:   DefaultMethod,
		ExtraVMs: []did.VerificationMethodSpec{did.NewSpec(did.NewSecp256k1VM("did:nda:0xabc", "#key-2", "0x03"))},
	}

	var dst DIDConfig
	WithDIDConfig(src)(&dst)

	if len(dst.ExtraVMs) != 1 {
		t.Fatalf("ExtraVMs dropped by WithDIDConfig: %+v", dst.ExtraVMs)
	}
	if dst.ExtraVMs[0].VM.Id != "did:nda:0xabc#key-2" {
		t.Fatalf("unexpected verification method: %+v", dst.ExtraVMs[0].VM)
	}
}

func TestWithVerificationMethods_Appends(t *testing.T) {
	var cfg DIDConfig

	WithVerificationMethods(did.NewSpec(did.NewSecp256k1VM("did:nda:0xabc", "#key-2", "0x03")))(&cfg)
	WithVerificationMethods(did.NewSpec(did.NewSecp256k1VM("did:nda:0xabc", "#key-3", "0x04")))(&cfg)

	if len(cfg.ExtraVMs) != 2 {
		t.Fatalf("expected 2 specs, got %d", len(cfg.ExtraVMs))
	}
}

// The P-256 VM is opt-in: a default config stays at one verification method.
func TestEnableP256VM_OptIn(t *testing.T) {
	var cfg DIDConfig
	if cfg.EnableP256VM {
		t.Fatal("EnableP256VM must default to false")
	}

	WithP256VerificationMethod()(&cfg)
	if !cfg.EnableP256VM {
		t.Fatal("WithP256VerificationMethod did not set the flag")
	}

	var dst DIDConfig
	WithDIDConfig(&cfg)(&dst)
	if !dst.EnableP256VM {
		t.Fatal("EnableP256VM dropped by WithDIDConfig")
	}
}
