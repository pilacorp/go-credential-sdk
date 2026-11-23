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
