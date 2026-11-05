package processor

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	ld "github.com/piprate/json-gold/ld"
)

var linkContext = map[string]interface{}{
	"knows": map[string]interface{}{"@id": "https://example.org/knows", "@type": "@id"},
	"name":  "https://example.org/name",
}

func graphOf(nodes int, targets func(i int) []int) map[string]interface{} {
	graph := make([]interface{}, nodes)
	for i := range graph {
		var links []interface{}
		for _, j := range targets(i) {
			links = append(links, map[string]interface{}{"@id": fmt.Sprintf("_:n%d", j)})
		}
		graph[i] = map[string]interface{}{"@id": fmt.Sprintf("_:n%d", i), "knows": links}
	}
	return map[string]interface{}{"@context": linkContext, "@graph": graph}
}

// blankClique is the attack: every node links to every other. 9 nodes is 1.4 KB
// and took json-gold 37 seconds.
func blankClique(nodes int) map[string]interface{} {
	return graphOf(nodes, func(i int) []int {
		var others []int
		for j := 0; j < nodes; j++ {
			if j != i {
				others = append(others, j)
			}
		}
		return others
	})
}

// blankCycle costs only polynomial time: 1000 nodes is 40 KB and took 38 seconds.
func blankCycle(nodes int) map[string]interface{} {
	return graphOf(nodes, func(i int) []int { return []int{(i + 1) % nodes} })
}

func canonicalizers() map[string]func(map[string]interface{}) error {
	return map[string]func(map[string]interface{}) error{
		"CanonicalizeDocument": func(d map[string]interface{}) error {
			_, err := CanonicalizeDocument(d)
			return err
		},
		"Canonicalize": func(d map[string]interface{}) error {
			_, err := Canonicalize(d)
			return err
		},
		"CanonicalizeWithIdMap": func(d map[string]interface{}) error {
			_, _, err := CanonicalizeWithIdMap(d)
			return err
		},
		"CanonicalizeNQuadsWithIdMap": func(d map[string]interface{}) error {
			nquads, err := ToRDFNQuads(d)
			if err != nil {
				return err
			}
			_, _, err = CanonicalizeNQuadsWithIdMap(nquads)
			return err
		},
	}
}

func TestCanonicalize_RefusesExpensiveBlankNodes(t *testing.T) {
	for name, doc := range map[string]map[string]interface{}{
		"clique of 9":   blankClique(9),
		"clique of 40":  blankClique(40),
		"cycle of 1000": blankCycle(1000),
	} {
		for fn, canonicalize := range canonicalizers() {
			t.Run(name+"/"+fn, func(t *testing.T) {
				start := time.Now()
				err := canonicalize(doc)
				if !errors.Is(err, ErrBlankNodeWork) {
					t.Fatalf("expected a refusal, got %v", err)
				}
				if elapsed := time.Since(start); elapsed > time.Second {
					t.Fatalf("refusal took %v", elapsed)
				}
			})
		}
	}
}

// What the cap must let through. Nodes that differ in their data cost nothing,
// however many; interchangeable proofs are the one repeat real documents have.
func TestCanonicalize_AcceptsCredentialShapes(t *testing.T) {
	anonymous := make([]interface{}, 300)
	identical := make([]interface{}, 300)
	for i := range anonymous {
		anonymous[i] = map[string]interface{}{"name": fmt.Sprintf("course %d", i)}
		identical[i] = map[string]interface{}{"name": "same"}
	}
	proof := func(graph, id string) map[string]interface{} {
		return map[string]interface{}{"@id": graph, "@graph": []interface{}{
			map[string]interface{}{"@id": id, "name": "same proof"},
		}}
	}

	for name, doc := range map[string]map[string]interface{}{
		"300 anonymous objects":  {"@context": linkContext, "knows": anonymous},
		"300 identical objects":  {"@context": linkContext, "knows": identical},
		"interchangeable proofs": {"@context": linkContext, "@graph": []interface{}{proof("_:g1", "_:p1"), proof("_:g2", "_:p2")}},
		"list of one value": {
			"@context": map[string]interface{}{"values": map[string]interface{}{"@id": "https://example.org/values", "@container": "@list"}},
			"values":   repeated("x", 60),
		},
	} {
		for fn, canonicalize := range canonicalizers() {
			t.Run(name+"/"+fn, func(t *testing.T) {
				if err := canonicalize(doc); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func repeated(value string, times int) []interface{} {
	list := make([]interface{}, times)
	for i := range list {
		list[i] = value
	}
	return list
}

// A clique just inside the score must stay cheap: the limit bounds the time.
func TestBlankNodeWork_LimitIsCheap(t *testing.T) {
	dataset, err := toRDFDataset(blankClique(3))
	if err != nil {
		t.Fatal(err)
	}
	if work := blankNodeWork(dataset); work == 0 || work > maxBlankNodeWork {
		t.Fatalf("clique of 3 scored %d", work)
	}
	start := time.Now()
	if _, err := normalizeDataset(dataset); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("took %v", elapsed)
	}
}

// CanonicalizeDocument took apart processor.Normalize to fit the check in. Its
// signatures depend on the bytes, so they must be Normalize's.
func TestCanonicalizeDocument_MatchesNormalize(t *testing.T) {
	doc := docWithUndefinedTerm()
	doc["proof"] = map[string]interface{}{"type": "DataIntegrityProof", "cryptosuite": "ecdsa-rdfc-2019"}

	got, err := CanonicalizeDocument(doc)
	if err != nil {
		t.Fatal(err)
	}

	standardized, err := standardizeToJSONLD(doc)
	if err != nil {
		t.Fatal(err)
	}
	opts := ld.NewJsonLdOptions("")
	opts.Format = "application/n-quads"
	opts.Algorithm = ld.AlgorithmURDNA2015
	opts.DocumentLoader = defaultDocumentLoader
	opts.SafeMode = true
	want, err := ld.NewJsonLdProcessor().Normalize(standardized, opts)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

// normalizationInputs are the rdf-canon inputs, which json-gold ships as the
// URDNA2015 suite. go test puts the go tool on PATH.
func normalizationInputs(t *testing.T) []string {
	t.Helper()
	dir, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/piprate/json-gold").Output()
	if err != nil {
		t.Fatal(err)
	}
	inputs, err := filepath.Glob(filepath.Join(strings.TrimSpace(string(dir)), "ld", "testdata", "normalization", "*-in.nq"))
	if err != nil || len(inputs) == 0 {
		t.Fatalf("no inputs: %v", err)
	}
	return inputs
}

// Signatures depend on these bytes, so they must stay what Main writes.
func TestCanonicalNQuads_MatchesMain(t *testing.T) {
	for _, path := range normalizationInputs(t) {
		t.Run(filepath.Base(path), func(t *testing.T) {
			input, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			parse := func() *ld.RDFDataset {
				dataset, err := ld.ParseNQuads(string(input))
				if err != nil {
					t.Fatal(err)
				}
				return dataset
			}
			opts := sdOptions()
			opts.Format = "application/n-quads"
			want, err := ld.NewNormalisationAlgorithm(ld.AlgorithmURDNA2015).Main(parse(), opts)
			if err != nil {
				t.Fatal(err)
			}
			got, err := canonicalNQuads(parse())
			if err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Fatalf("got:\n%s\nwant:\n%s", got, want)
			}
		})
	}
}

// Main joins its lines with +=, which allocates the square of the output.
func TestNormalizeDataset_AllocatesLinearly(t *testing.T) {
	dataset, err := toRDFDataset(map[string]interface{}{
		"@context": map[string]interface{}{"values": map[string]interface{}{"@id": "https://example.org/values", "@container": "@list"}},
		"@id":      "https://example.org/subject",
		"values":   numbers(3000),
	})
	if err != nil {
		t.Fatal(err)
	}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	if _, err := normalizeDataset(dataset); err != nil {
		t.Fatal(err)
	}
	runtime.ReadMemStats(&after)
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 100<<20 {
		t.Fatalf("allocated %d MiB", allocated>>20)
	}
}

func numbers(n int) []interface{} {
	list := make([]interface{}, n)
	for i := range list {
		list[i] = float64(i)
	}
	return list
}
