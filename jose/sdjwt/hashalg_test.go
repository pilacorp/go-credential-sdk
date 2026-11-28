package sdjwt

import (
	"crypto/sha512"
	"errors"
	"reflect"
	"testing"

	"github.com/pilacorp/go-credential-sdk/jose"
)

// RFC 9901 §4.1.1: a digest is base64url(hash(disclosure)) with the hash
// _sd_alg names. Conceal with sha-384 and sha-512 writes that _sd_alg and
// those digests; Recreate gives the claims back only when it accepts the alg.
func TestHashAlgorithms(t *testing.T) {
	for alg, sum := range map[string]func(string) []byte{
		AlgSHA384: func(s string) []byte { h := sha512.Sum384([]byte(s)); return h[:] },
		AlgSHA512: func(s string) []byte { h := sha512.Sum512([]byte(s)); return h[:] },
	} {
		t.Run(alg, func(t *testing.T) {
			payload, ds, err := Conceal(roundTripClaims(), []Path{{"given_name"}}, ConcealOptions{Algorithm: alg})
			if err != nil {
				t.Fatal(err)
			}
			if payload["_sd_alg"] != alg {
				t.Fatalf("_sd_alg %v", payload["_sd_alg"])
			}
			want := jose.EncodeSegment(sum(ds[0].Encoded))
			if sd := payload["_sd"].([]any); len(sd) != 1 || sd[0] != want {
				t.Fatalf("_sd %v, want [%s]", sd, want)
			}
			// §4.2.5: decoys use the same hash, so they have its length; and a
			// decoys-only payload still names it.
			padded, _, err := Conceal(roundTripClaims(), nil, ConcealOptions{Algorithm: alg, Decoys: []Decoy{{Path: Path{}, Count: 3}}})
			if err != nil {
				t.Fatal(err)
			}
			if padded["_sd_alg"] != alg {
				t.Errorf("decoys only: _sd_alg %v", padded["_sd_alg"])
			}
			for _, d := range padded["_sd"].([]any) {
				if len(d.(string)) != len(want) {
					t.Errorf("decoy %v has %d characters, a %s digest %d", d, len(d.(string)), alg, len(want))
				}
			}
			if _, err := Recreate(payload, ds); !errors.Is(err, jose.ErrMalformed) {
				t.Fatalf("Recreate by default: %v, want ErrMalformed", err)
			}
			r, err := RecreateWithOptions(payload, ds, RecreateOptions{Algorithms: []string{AlgSHA256, alg}})
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(r.Claims, roundTripClaims()) || r.Alg != alg {
				t.Fatalf("claims %v, alg %s", r.Claims, r.Alg)
			}
			if got, ok := r.Disclosures(Path{"given_name"}); !ok || len(got) != 1 || got[0].Digest != want {
				t.Errorf("Disclosures digest %v, want %s", got, want)
			}
		})
	}
	if _, _, err := Conceal(roundTripClaims(), nil, ConcealOptions{Algorithm: "md5"}); !errors.Is(err, jose.ErrUnsupportedAlg) {
		t.Errorf("Conceal md5: %v", err)
	}
	if _, err := RecreateWithOptions(map[string]any{}, nil, RecreateOptions{Algorithms: []string{"SHA-256"}}); !errors.Is(err, jose.ErrUnsupportedAlg) {
		t.Errorf("Recreate SHA-256 upper case: %v", err)
	}
	// §4.1.1: _sd_alg is a string; absent means sha-256, which a list
	// without it refuses (§7.1 step 2d).
	if _, err := RecreateWithOptions(map[string]any{"_sd_alg": 384}, nil, RecreateOptions{Algorithms: []string{AlgSHA384}}); !errors.Is(err, jose.ErrMalformed) {
		t.Errorf("_sd_alg a number: %v", err)
	}
	if _, err := RecreateWithOptions(map[string]any{}, nil, RecreateOptions{Algorithms: []string{AlgSHA384}}); !errors.Is(err, jose.ErrMalformed) {
		t.Errorf("no _sd_alg, sha-256 not accepted: %v", err)
	}
}

// Decoys at a path add exactly Count digests there and nowhere else.
func TestConcealDecoysAtPath(t *testing.T) {
	payload, ds, err := Conceal(roundTripClaims(), []Path{{"address", "locality"}}, ConcealOptions{
		Decoys: []Decoy{{Path: Path{"address"}, Count: 2}, {Path: Path{"nationalities"}, Count: 3}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if sd := payload["address"].(map[string]any)["_sd"].([]any); len(sd) != 3 {
		t.Errorf("address _sd has %d digests, want 1 concealed + 2 decoys", len(sd))
	}
	if n := len(payload["nationalities"].([]any)); n != 5 {
		t.Errorf("nationalities has %d elements, want 2 + 3 decoys", n)
	}
	if _, ok := payload["_sd"]; ok {
		t.Errorf("top level got decoys: %v", payload["_sd"])
	}
	r, err := Recreate(payload, ds)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r.Claims, roundTripClaims()) {
		t.Fatalf("claims %v", r.Claims)
	}
	// Decoys come on top of the MinDigests padding.
	padded, _, err := Conceal(map[string]any{"a": 1}, nil, ConcealOptions{MinDigests: 5, Decoys: []Decoy{{Path: Path{}, Count: 3}}})
	if err != nil {
		t.Fatal(err)
	}
	if n := len(padded["_sd"].([]any)); n != 8 {
		t.Errorf("top-level _sd has %d digests, want 5 + 3", n)
	}
	arr, _, err := Conceal(map[string]any{"a": []any{"x"}}, nil, ConcealOptions{MinDigests: 2, Decoys: []Decoy{{Path: Path{"a"}, Count: 3}}})
	if err != nil {
		t.Fatal(err)
	}
	if n := len(arr["a"].([]any)); n != 6 {
		t.Errorf("array has %d elements, want 1 + 2 padding + 3 decoys", n)
	}
	if _, _, err := Conceal(roundTripClaims(), nil, ConcealOptions{NoArrayDecoys: true, Decoys: []Decoy{{Path: Path{"nationalities"}, Count: 1}}}); !errors.Is(err, jose.ErrInvalidArgument) {
		t.Errorf("array decoy with NoArrayDecoys: %v", err)
	}
	// Decoys inside a concealed claim go into its disclosure, and decoys at an
	// object inside an array go to that object.
	inner, ids, err := Conceal(map[string]any{
		"address": map[string]any{"city": "x"},
		"list":    []any{map[string]any{"k": 1}},
	}, []Path{{"address"}}, ConcealOptions{Decoys: []Decoy{
		{Path: Path{"address"}, Count: 2}, {Path: Path{"list", 0}, Count: 3},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if n := len(ids[0].Value.(map[string]any)["_sd"].([]any)); n != 2 {
		t.Errorf("concealed address holds %d decoys, want 2", n)
	}
	if n := len(inner["list"].([]any)[0].(map[string]any)["_sd"].([]any)); n != 3 {
		t.Errorf("list[0] holds %d decoys, want 3", n)
	}
	// The 20000-digest cap counts MinDigests padding and every Decoys count.
	many := map[string]any{}
	var full []Decoy
	for i := 0; i < 20; i++ {
		k := string(rune('a' + i))
		many[k] = map[string]any{"v": 1}
		full = append(full, Decoy{Path: Path{k}, Count: 1000})
	}
	if _, _, err := Conceal(many, nil, ConcealOptions{Decoys: full}); err != nil {
		t.Errorf("20000 decoys: %v", err)
	}
	if _, _, err := Conceal(many, nil, ConcealOptions{MinDigests: 1, Decoys: full}); !errors.Is(err, jose.ErrInvalidArgument) {
		t.Errorf("20000 decoys plus padding: %v, want refused", err)
	}
	for _, bad := range [][]Decoy{
		{{Path: Path{"given_name"}, Count: 1}},
		{{Path: Path{"missing"}, Count: 1}},
		{{Path: Path{"address"}, Count: 0}},
		{{Path: Path{"address"}, Count: 1001}},
		{{Path: Path{"nationalities", int64(0)}, Count: 1}},
		{{Path: Path{"address"}, Count: 1}, {Path: Path{"address"}, Count: 1}},
	} {
		if _, _, err := Conceal(roundTripClaims(), nil, ConcealOptions{Decoys: bad}); !errors.Is(err, jose.ErrInvalidArgument) {
			t.Errorf("Decoys %v: %v", bad, err)
		}
	}
}

// RFC 9901 §4.3.1: sd_hash uses the _sd_alg hash.
func TestSDHashWith(t *testing.T) {
	const s = "eyJ.x.y~WyJhIiwiYiIsImMiXQ~"
	h := sha512.Sum384([]byte(s))
	if got, err := SDHashWith(s, AlgSHA384); err != nil || got != jose.EncodeSegment(h[:]) {
		t.Errorf("sha-384: %q %v", got, err)
	}
	if got, _ := SDHashWith(s, AlgSHA256); got != SDHash(s) {
		t.Errorf("sha-256 %q differs from SDHash", got)
	}
	if _, err := SDHashWith(s, "sha3-256"); !errors.Is(err, jose.ErrUnsupportedAlg) {
		t.Errorf("sha3-256: %v", err)
	}
}

// Array decoys go at uniformly random positions (§4.2.5 decoys must not be
// told from real digests by where they sit): over many runs a decoy lands
// both before and after an element, and two decoys at both ends.
func TestArrayDecoyPositionsVary(t *testing.T) {
	positions := map[int]bool{}
	ends := map[string]bool{}
	for i := 0; i < 300 && (len(positions) < 2 || len(ends) < 2); i++ {
		one, _, err := Conceal(map[string]any{"a": []any{"x"}}, nil, ConcealOptions{Decoys: []Decoy{{Path: Path{"a"}, Count: 1}}})
		if err != nil {
			t.Fatal(err)
		}
		for j, el := range one["a"].([]any) {
			if el == "x" {
				positions[j] = true
			}
		}
		two, _, err := Conceal(map[string]any{"a": []any{"x", "y"}}, nil, ConcealOptions{Decoys: []Decoy{{Path: Path{"a"}, Count: 2}}})
		if err != nil {
			t.Fatal(err)
		}
		arr := two["a"].([]any)
		if _, ok := arr[0].(map[string]any); ok {
			ends["first"] = true
		}
		if _, ok := arr[len(arr)-1].(map[string]any); ok {
			ends["last"] = true
		}
	}
	if len(positions) < 2 || len(ends) < 2 {
		t.Fatalf("decoy positions never varied: element at %v, decoys at ends %v", positions, ends)
	}
}

// DigestWith is the §4.2.3 digest: the RFC's example disclosure and its
// sha-256 digest.
func TestDigestWithRFCExample(t *testing.T) {
	got, err := DigestWith("WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0", AlgSHA256)
	if err != nil || got != "X9yH0Ajrdm1Oij4tWso9UzzKJvPoDxwmuEcO3XAdRC0" {
		t.Fatalf("DigestWith = %q, %v", got, err)
	}
	if _, err := DigestWith("x", "sha3-256"); !errors.Is(err, jose.ErrUnsupportedAlg) {
		t.Fatalf("sha3-256: %v", err)
	}
}
