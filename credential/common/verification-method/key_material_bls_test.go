package verificationmethod

import "testing"

func TestPublicKeyMultibaseBytesFromVM_BLS12381G2StripsMulticodecPrefix(t *testing.T) {
	vm := &VerificationMethodEntry{
		ID: "did:example:issuer#key-1",
		PublicKeyMultibase: "zUC7DerdEmfZ8f4pFajXgGwJoMkV1ofMTmEG5UoNvnWiPiLuGKNeqgRpLH2TV4Xe5mJ2cXV76gRN7LFQwapF1VFu6x2yrr5ci1mXqC1WNUrnHnLgvfZfMH7h6xP6qsf9EKRQrPQ",
	}

	raw, err := PublicKeyMultibaseBytesFromVM(vm)
	if err != nil {
		t.Fatalf("decode multibase: %v", err)
	}
	if got, want := len(raw), 96; got != want {
		t.Fatalf("decoded key length = %d, want %d", got, want)
	}
	if got, want := raw[0], byte(0xa4); got != want {
		t.Fatalf("first public key byte = 0x%02x, want 0x%02x", got, want)
	}
}
