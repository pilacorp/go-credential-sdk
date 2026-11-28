package ecdsasd

import (
	"strings"
	"testing"
)

// A label map with several malformed keys names the same key on every run.
func TestCompressLabelMapErrorIsStable(t *testing.T) {
	labelMap := map[string]string{"c14nb": "uAA", "c14na": "uAA", "c14n0": "uAA"}
	for i := 0; i < 50; i++ {
		_, err := compressLabelMap(labelMap)
		if err == nil || !strings.Contains(err.Error(), `"c14na"`) {
			t.Fatalf("run %d: compressLabelMap = %v, want the error to name key \"c14na\"", i, err)
		}
	}
}

// A proof value has one spelling (RFC 4648 §3.5): the W3C vector parses, the
// same bytes written with a line break or with set pad bits do not.
func TestProofValueRefusesOtherSpellings(t *testing.T) {
	pv := w3cLoadExpected(t).BaseProofValue
	if _, err := parseBaseProofValue(pv); err != nil {
		t.Fatalf("vector: %v", err)
	}
	if (len(pv)-1)%4 == 0 {
		t.Fatal("vector has no pad bits to set")
	}
	last := strings.Index(base64URL, pv[len(pv)-1:])
	padBits := base64URL[last+1 : last+2] // same decoded bytes, a low bit set
	for name, alias := range map[string]string{
		"CR/LF":    pv[:10] + "\r\n" + pv[10:],
		"pad bits": pv[:len(pv)-1] + padBits,
	} {
		if _, err := parseBaseProofValue(alias); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := compressLabelMap(map[string]string{"c14n0": "AAAA"}); err == nil {
		t.Error("label map value without the 'u' prefix accepted")
	}
}

const base64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
