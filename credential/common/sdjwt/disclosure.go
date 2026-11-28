package sdjwt

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/pilacorp/go-credential-sdk/credential/common/util"
	"github.com/pilacorp/go-credential-sdk/credential/internal/jwtutil"
	"github.com/pilacorp/go-credential-sdk/jose"
	josesdjwt "github.com/pilacorp/go-credential-sdk/jose/sdjwt"
)

// Hash algorithms for _sd_alg (RFC 9901 §4.1.1).
const (
	AlgSHA256 = josesdjwt.AlgSHA256
	AlgSHA384 = josesdjwt.AlgSHA384
	AlgSHA512 = josesdjwt.AlgSHA512

	DefaultHashAlgorithm = AlgSHA256
)

// supportedHashAlgorithms are the _sd_alg values Reconstruct accepts.
var supportedHashAlgorithms = []string{AlgSHA256, AlgSHA384, AlgSHA512}

// DecoyConfig specifies where and how many decoy digests to add.
type DecoyConfig struct {
	Path  string // parent path where decoy digests should be added (e.g. "", "credentialSubject").
	Count int    // number of decoy digests to add at this path.
}

// BuildDisclosuresInput is the input struct for BuildDisclosures.
type BuildDisclosuresInput struct {
	VC             map[string]interface{} // VC payload to process
	SelectivePaths []string               // field paths to make selectively disclosable
	HashAlgorithm  string                 // hash algorithm (sha-256, sha-384, sha-512). Empty defaults to sha-256.
	// Deprecated: Shuffle has no effect: _sd is always sorted (RFC 9901
	// §4.2.4.1) and array decoys (§4.2.5) go at random positions.
	Shuffle bool
	Decoys  []DecoyConfig // decoy digests to add at specific paths.
}

// SDJWTResult contains the result of BuildDisclosures.
// Holder-facing metadata is available via Parse() -> ParsedSDJWT.DecodedDisclosures.
type SDJWTResult struct {
	ProcessedVC map[string]interface{} // VC with fields replaced by digests
	// Disclosures are the disclosure strings (base64url), deeper paths first,
	// then by path; not in the order of SelectivePaths.
	Disclosures []string
}

// BuildDisclosures is used at issuing time to construct SD-JWT structures.
// It takes a plain VC payload and a list of field paths (dot + [index]
// notation) that should be selectively disclosable, and runs
// jose/sdjwt.Conceal on them, so issuing and verifying share one SD-JWT
// implementation.
//
// Supported path format examples:
//   - "firstname"
//   - "person.firstname"
//   - "person.address.city"
//   - "tags[0]"
//   - "person.children[0].name"
//
// A decoy path names an object (decoys go to its _sd) or an array (decoys
// become placeholders at random positions). A path to an array element adds
// to that array, and a path to any other value adds to the object holding it.
// A path that is not in VC is an error. Decoys with Count <= 0 are skipped.
//
// When something is concealed, ProcessedVC is read back as JSON: numbers are
// float64, as encoding/json decodes them, but an integer literal past ±2^53
// stays a json.Number so the signed digits do not change.
//
// With no path and no decoy, VC is returned as a copy, unchanged. Otherwise
// digests a caller built earlier and left in VC (_sd, array placeholders) are
// kept and merged with the new ones. A digest of another length than the
// hash gives, or a top-level _sd_alg that names another hash, is refused. A
// path may not name such a placeholder or a claim holding such digests.
func BuildDisclosures(input BuildDisclosuresInput) (*SDJWTResult, error) {
	alg := input.HashAlgorithm
	if alg == "" {
		alg = DefaultHashAlgorithm
	}
	// Checked here, not left to Conceal: the prebuilt-digest checks below
	// measure digests by this hash before Conceal runs.
	if _, err := josesdjwt.DigestWith("", alg); err != nil {
		return nil, err
	}

	paths := make([]josesdjwt.Path, 0, len(input.SelectivePaths))
	for _, raw := range input.SelectivePaths {
		p := strings.TrimSpace(raw)
		if p == "" {
			return nil, fmt.Errorf("%w: empty path", jose.ErrInvalidArgument)
		}
		jp, err := parsePath(p)
		if err != nil {
			return nil, err
		}
		paths = append(paths, jp)
	}
	// Nothing to conceal: the VC comes back as a copy with the caller's Go
	// types, as before, since every plain vc+jwt passes through here.
	if len(paths) == 0 && !hasDecoys(input.Decoys) {
		return &SDJWTResult{ProcessedVC: util.DeepCopyMap(input.VC)}, nil
	}

	// Conceal reads the claims as JSON, so typed Go values ([]string,
	// map[string]string, structs) are read here the same way: decoy paths
	// then name the containers Conceal sees.
	claims, err := jsonTree(input.VC)
	if err != nil {
		return nil, err
	}
	pre, err := holdPrebuilt(claims, alg)
	if err != nil {
		return nil, err
	}

	var decoys []josesdjwt.Decoy
	for _, d := range input.Decoys {
		if d.Count <= 0 {
			continue
		}
		at, err := decoyTarget(claims, d.Path)
		if err != nil {
			return nil, err
		}
		decoys = append(decoys, josesdjwt.Decoy{Path: at, Count: d.Count})
	}

	merged, err := mergeDecoys(decoys)
	if err != nil {
		return nil, err
	}
	payload, ds, err := josesdjwt.Conceal(claims, paths, josesdjwt.ConcealOptions{
		Algorithm: alg,
		Decoys:    merged,
	})
	if err != nil {
		return nil, inDotNotation(err)
	}
	if err := pre.restore(payload); err != nil {
		return nil, err
	}
	processed, err := jwtutil.FloatNumbersExact(payload)
	if err != nil {
		return nil, err
	}
	disclosures := make([]string, len(ds))
	for i, d := range ds {
		disclosures[i] = d.Encoded
	}
	return &SDJWTResult{ProcessedVC: processed.(map[string]interface{}), Disclosures: disclosures}, nil
}

func hasDecoys(decoys []DecoyConfig) bool {
	for _, d := range decoys {
		if d.Count > 0 {
			return true
		}
	}
	return false
}

// jsonTree copies vc through module jose's JSON encoder and reader.
func jsonTree(vc map[string]interface{}) (map[string]interface{}, error) {
	b, err := jose.EncodeJSON(vc)
	if err != nil {
		return nil, fmt.Errorf("encode VC: %w", err)
	}
	m, err := jose.DecodeJSONObject(b)
	if err != nil {
		return nil, fmt.Errorf("%w: read VC as JSON: %v", jose.ErrInvalidArgument, err)
	}
	return m, nil
}

// prebuilt holds the digests a caller put in the VC itself (the advanced path:
// its own BuildDisclosures output, passed back with its disclosures). Conceal
// refuses _sd and "..." in its input, so holdPrebuilt moves each under a
// random key and restore puts them back, _sd merged with Conceal's and
// sorted (RFC 9901 §4.2.4.1).
type prebuilt struct {
	sdKey, elKey string // stand-ins for "_sd" and an array placeholder's "..."
	count        int
	digestLen    int   // length of a base64url digest of the hash in use
	err          error // the first prebuilt digest of another length
}

func holdPrebuilt(claims map[string]interface{}, alg string) (*prebuilt, error) {
	if v, ok := claims["_sd_alg"]; ok {
		if v != alg {
			return nil, fmt.Errorf("%w: VC holds _sd_alg %.32q, but the hash algorithm is %q", jose.ErrInvalidArgument, fmt.Sprint(v), alg)
		}
		delete(claims, "_sd_alg")
	}
	b := make([]byte, 16)
	rand.Read(b) // never returns an error since Go 1.24
	key := "sdjwt-prebuilt-" + hex.EncodeToString(b)
	p := &prebuilt{sdKey: key + "-sd", elKey: key + "-el", digestLen: digestLen(alg)}
	p.hold(claims, false)
	return p, p.err
}

// digestLen is the length of base64url(hash) for alg, taken from jose so
// the two cannot drift.
func digestLen(alg string) int {
	d, _ := josesdjwt.DigestWith("", alg) // alg was checked by the caller
	return len(d)
}

func isBase64URL(s string) bool {
	_, err := jose.DecodeSegment(s)
	return err == nil
}

// check refuses a prebuilt digest, in _sd or an array placeholder (where),
// that is not a string of the hash's digest length: one made with another
// hash would match no disclosure under alg.
func (p *prebuilt) check(where string, d interface{}) {
	if p.err != nil {
		return
	}
	if s, ok := d.(string); !ok || len(s) != p.digestLen || !isBase64URL(s) {
		p.err = fmt.Errorf("%w: the VC holds %s %.64q, which is not a %d-character digest: the digests already in the VC were made with another hash; use one hash throughout (BuildDisclosuresInput.HashAlgorithm, and vc.WithSDHashAlgorithm when building through vc)", jose.ErrInvalidArgument, where, fmt.Sprint(d), p.digestLen)
	}
}

// hold walks v; inArray says v is an array element, the only place a
// placeholder may be (RFC 9901 §4.1 item 7, §4.2.4.2). A "..." anywhere else stays, and
// Conceal refuses it as a reserved name.
func (p *prebuilt) hold(v interface{}, inArray bool) {
	switch t := v.(type) {
	case map[string]interface{}:
		if d, ok := t["..."]; ok && len(t) == 1 && inArray {
			p.check("an array placeholder", d)
			delete(t, "...")
			t[p.elKey] = d
			p.count++
			return
		}
		// A _sd that is not an array stays, and Conceal refuses it.
		if sd, ok := t["_sd"].([]interface{}); ok {
			for _, d := range sd {
				p.check("an _sd digest", d)
			}
			delete(t, "_sd")
			t[p.sdKey] = sd
			p.count++
		}
		for k, el := range t {
			if k != p.sdKey { // digests, already checked
				p.hold(el, false)
			}
		}
	case []interface{}:
		for _, el := range t {
			p.hold(el, true)
		}
	}
}

func (p *prebuilt) restore(payload map[string]interface{}) error {
	if p.count == 0 {
		return nil
	}
	if p.put(payload) != p.count {
		return fmt.Errorf("%w: a selective path names a prebuilt placeholder, or a claim holding prebuilt digests: conceal those claims in the call that built their disclosures", jose.ErrInvalidArgument)
	}
	return nil
}

func (p *prebuilt) put(v interface{}) int {
	n := 0
	switch t := v.(type) {
	case map[string]interface{}:
		if d, ok := t[p.elKey]; ok {
			delete(t, p.elKey)
			t["..."] = d
			return 1
		}
		if held, ok := t[p.sdKey]; ok {
			delete(t, p.sdKey)
			n++
			merged, _ := held.([]interface{})
			if sd, ok := t["_sd"].([]interface{}); ok {
				merged = append(merged, sd...)
			}
			// Every element is a string: check refused anything else.
			sort.Slice(merged, func(i, j int) bool {
				a, _ := merged[i].(string)
				b, _ := merged[j].(string)
				return a < b
			})
			t["_sd"] = merged
		}
		for _, el := range t {
			n += p.put(el)
		}
	case []interface{}:
		for _, el := range t {
			n += p.put(el)
		}
	}
	return n
}

// decoyTarget maps a decoy path to the object or array that receives the
// decoys, following the rules in BuildDisclosures.
func decoyTarget(vc map[string]interface{}, path string) (josesdjwt.Path, error) {
	p := josesdjwt.Path{}
	if strings.TrimSpace(path) != "" {
		var err error
		if p, err = parsePath(path); err != nil {
			return nil, err
		}
	}
	var v interface{} = vc
	for i, el := range p {
		switch k := el.(type) {
		case string:
			m, ok := v.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("%w: decoy path %.64q: %.64q is not in an object", jose.ErrInvalidArgument, path, k)
			}
			if v, ok = m[k]; !ok {
				return nil, fmt.Errorf("%w: decoy path %.64q is not in the credential", jose.ErrInvalidArgument, path)
			}
		case int:
			a, ok := v.([]interface{})
			if !ok || k < 0 || k >= len(a) {
				return nil, fmt.Errorf("%w: decoy path %.64q is not in the credential", jose.ErrInvalidArgument, path)
			}
			if i == len(p)-1 {
				return p[:i], nil // an element: the array holding it
			}
			v = a[k]
		}
	}
	switch v.(type) {
	case map[string]interface{}, []interface{}:
		return p, nil
	}
	return p[:len(p)-1], nil // a value: the object holding it
}

// mergeDecoys adds up counts given twice for one target, as the earlier
// implementation appended both.
func mergeDecoys(decoys []josesdjwt.Decoy) ([]josesdjwt.Decoy, error) {
	out := make([]josesdjwt.Decoy, 0, len(decoys))
	at := make(map[string]int, len(decoys))
	for _, d := range decoys {
		i, ok := at[d.Path.String()]
		if !ok {
			at[d.Path.String()] = len(out)
			out = append(out, d)
			continue
		}
		// Conceal caps a count at 1000; the sum must not wrap before it sees it.
		if out[i].Count > math.MaxInt-d.Count {
			return nil, fmt.Errorf("%w: decoy counts for one path add up past %d", jose.ErrInvalidArgument, math.MaxInt)
		}
		out[i].Count += d.Count
	}
	return out, nil
}

// inDotNotation writes the claim path a Conceal error names in the dot +
// [index] notation callers use, quoted and cut at 64 characters before
// quoting, as this package's own errors are. Services pass this text on to
// whoever sent the paths. err still matches what it wrapped.
func inDotNotation(err error) error {
	var pe *josesdjwt.PathError
	if !errors.As(err, &pe) {
		return err
	}
	return &rewordedError{text: pe.Text(func(p josesdjwt.Path) string {
		return fmt.Sprintf("%.64q", dotPath(p))
	}), err: err}
}

type rewordedError struct {
	text string
	err  error
}

func (e *rewordedError) Error() string { return e.text }
func (e *rewordedError) Unwrap() error { return e.err }

// dotPath writes p as parsePath reads it, e.g. "person.children[0].name".
func dotPath(p josesdjwt.Path) string {
	var b strings.Builder
	for _, el := range p {
		switch v := el.(type) {
		case string:
			if b.Len() > 0 {
				b.WriteByte('.')
			}
			b.WriteString(v)
		case int:
			b.WriteByte('[')
			b.WriteString(strconv.Itoa(v))
			b.WriteByte(']')
		}
	}
	return b.String()
}

// parsePath parses a dot + [index] notation path, such as
// "person.children[0].name", into a jose/sdjwt Path.
func parsePath(path string) (josesdjwt.Path, error) {
	var out josesdjwt.Path
	for _, part := range strings.Split(path, ".") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		bracket := strings.Index(part, "[")
		if bracket == -1 {
			out = append(out, part)
			continue
		}
		key, rest := part[:bracket], part[bracket:]
		if !strings.HasSuffix(rest, "]") {
			return nil, fmt.Errorf("%w: invalid array segment %.64q in path %.64q", jose.ErrInvalidArgument, part, path)
		}
		idx := rest[1 : len(rest)-1]
		switch idx {
		case "":
			return nil, fmt.Errorf("%w: empty index in path %.64q", jose.ErrInvalidArgument, path)
		case "*":
			return nil, fmt.Errorf("%w: wildcard index '*' is not supported in path %.64q", jose.ErrInvalidArgument, path)
		}
		i, err := strconv.Atoi(idx)
		if err != nil || i < 0 {
			return nil, fmt.Errorf("%w: invalid index %.64q in path %.64q", jose.ErrInvalidArgument, idx, path)
		}
		if key != "" {
			out = append(out, key)
		}
		out = append(out, i)
	}
	return out, nil
}
