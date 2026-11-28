package crypto

import (
	"bytes"
	"testing"
)

// The tag must survive an append to the ciphertext.
func TestEncryptAESGCM_TagDoesNotAliasCiphertext(t *testing.T) {
	_, ciphertext, tag, err := EncryptAESGCM(make([]byte, 32), []byte("hello"), nil)
	if err != nil {
		t.Fatal(err)
	}
	before := append([]byte(nil), tag...)
	_ = append(ciphertext, 0xff)
	if !bytes.Equal(tag, before) {
		t.Fatalf("tag changed from %x to %x", before, tag)
	}
}
