package digitalcredential

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/pilacorp/go-credential-sdk/jose"
	"github.com/pilacorp/go-credential-sdk/jose/jwk"
	"github.com/pilacorp/go-credential-sdk/jose/jws"
	"github.com/pilacorp/go-credential-sdk/jose/sdjwt"
)

// draft-ietf-oauth-sd-jwt-vc-19 Appendix A.1, Figure 24: the issued PID
// SD-JWT. Disclosure 18 is ["OBKlTVlvLg-AdwqYGbP8ZA", "18", true], inside the
// concealed age_equal_or_over, which is disclosure 21.
const draft19A1Issued = "" +
	"eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImRjK3NkLWp3dCJ9.eyJfc2QiOiBbIjJyMDA5ZHp2SHVWcldyUlhUNWtKTW1IbnF" +
	"FSEhuV2UwTUxWWnc4UEFUQjgiLCAiM05kREpZUndCcWFFSXlYQ0hjbjRhNVlLSmFnUGdJUDBXa2c5QW9yZ0FLZyIsICI1Zm4" +
	"2SWlYalVQbUdRNG1ZSHhEZHQ2RWp2QlE3Z1J2R2NkRW5TQ0VOOEVrIiwgIjZCek1CazdGR2l2b2dibGRPNzVmM05Md2pGbGl" +
	"DcWI3bm4xR2hnQ29rclEiLCAiOTBDVDhBYUJQYm41WDhuUlhrZXNqdTFpMEJxaFdxWjN3cUQ0akYtcURHayIsICI5bkV3VXJ" +
	"kZVo2a2NSYkVqNTJRSDNuT1Itb2llMF9wOXRNTklBRXVGdk1VIiwgIkhUaDZacjJKOGFpcXBhOTYzY0xrdUtlUURmOU8wMEZ" +
	"6T0hoeWpHcFZmVGciLCAiSkNwMksyTmhILUxFNUwwajdNRTBMTngtVC1weDlRRnRhbVNzeG1DVUN4VSIsICJMb01HcmhsRG1" +
	"fYlVXVVgxZ2RoUnhUc3k0ZDR6eXdHemxTVm9jUlNZMDFNIiwgIlVnVWpxNXdoelFld081OWZWTmowZjBtcXlWOFlQWFU1NHN" +
	"wNGtMZWN3UWsiLCAiWTBILUUzaHpLRVVuQXlyaV94OXRUOWstajRpNjVhbzloa2VFSE5leG9zSSIsICJlekNBbWFUd0kyblB" +
	"qXzFJaUIzS1pmaUVPUkxlUndoWnNNTURNWklKOGtBIiwgImkwSF8tV0FId2ZFanQ4dHFRSDc0dU9DV3ZxdVkzRnd1WC1reDR" +
	"lMlJKSDgiLCAicjFHckg0NnlEVjYyc2V6SW1FanhhNmNKU1pNVDIxMmpyT1NIaWVjOXl0TSIsICJyVmozUkxzN0s4emROeTd" +
	"6WHoxQ3IzOVk2cm9nOHVsTm96azRGN05DdUMwIiwgInQ1a3AwSGZ4TVMxZUhOQ0dSenJLOUdpNW9UWnJlZzVVZTlsTFFJdUx" +
	"2QjQiXSwgImlzcyI6ICJodHRwczovL3BpZC1pc3N1ZXIuYWVuZGdhcmQuZXhhbXBsZSIsICJpYXQiOiAxNjgzMDAwMDAwLCA" +
	"iZXhwIjogMTg4MzAwMDAwMCwgInZjdCI6ICJ1cm46ZXhhbXBsZTpldWRpOnBpZDphZW5kZ2FyZDoxIiwgIl9zZF9hbGciOiA" +
	"ic2hhLTI1NiIsICJjbmYiOiB7Imp3ayI6IHsia3R5IjogIkVDIiwgImNydiI6ICJQLTI1NiIsICJ4IjogIlRDQUVSMTladnU" +
	"zT0hGNGo0VzR2ZlNWb0hJUDFJTGlsRGxzN3ZDZUdlbWMiLCAieSI6ICJaeGppV1diWk1RR0hWV0tWUTRoYlNJaXJzVmZ1ZWN" +
	"DRTZ0NGpUOUYySFpRIn19fQ.0bJ9ZMO36qi-SuLQaZZSGJMyA9yO5Z2sV_lxJyspURbkfmC4P9SlmNizVHyifDPtF9TgfJjK" +
	"MmvOxMsKSLAdJA~WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiQXN0cmlkIl0~WyJlbHVWNU9nM" +
	"2dTTklJOEVZbnN4QV9BIiwgImZhbWlseV9uYW1lIiwgIkhvbG1ncmVuIl0~WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgI" +
	"mJpcnRoZGF0ZSIsICIxOTc4LTA0LTEwIl0~WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgInN0cmVldF9hZGRyZXNzIiwgI" +
	"lNqXHUwMGY4Z2F0YSAxMiJd~WyJRZ19PNjR6cUF4ZTQxMmExMDhpcm9BIiwgImxvY2FsaXR5IiwgIlZpa2VuIl0~WyJBSngt" +
	"MDk1VlBycFR0TjRRTU9xUk9BIiwgInBvc3RhbF9jb2RlIiwgIjEyMDAxIl0~WyJQYzMzSk0yTGNoY1VfbEhnZ3ZfdWZRIiwg" +
	"ImNvdW50cnkiLCAiS2luZ2RvbSBvZiBcdTAwYzZuZGdhcmQiXQ~WyJHMDJOU3JRZmpGWFE3SW8wOXN5YWpBIiwgImFkZHJlc" +
	"3MiLCB7Il9zZCI6IFsiNjBCM0N3cTA0aGxQQndzdnNmdks5SlV4dnVMRlViSlFmZ1BCYk9fSDlyTSIsICI4eWpQUjNyOGRPN" +
	"UhXTG55MWdCZU1KVFBSZ2tCY2h1cTQzcUg4V2xfZjFjIiwgIk5hcmQ3NHcyTl85YW5WRW1TbGVjRUpscXgzanhiY3F4dlZ6Q" +
	"nNCRFgweHMiLCAiVS16RDFESS03WjB6WW94WHF5NUhTVE5VZWdhaFJDSHlkQWVzS09fc0VQYyJdfV0~WyJsa2x4RjVqTVlsR" +
	"1RQVW92TU5JdkNBIiwgIm5hdGlvbmFsaXRpZXMiLCBbIlx1MDBjNm5kZ2FyZCJdXQ~WyJuUHVvUW5rUkZxM0JJZUFtN0FuWE" +
	"ZBIiwgInNleCIsIDJd~WyI1YlBzMUlxdVpOYTBoa2FGenp6Wk53IiwgImJpcnRoX2ZhbWlseV9uYW1lIiwgIkplbnNlbiJd~" +
	"WyI1YTJXMF9OcmxFWnpmcW1rXzdQcS13IiwgImxvY2FsaXR5IiwgIlx1MDBjNm5kaG9sbSJd~WyJ5MXNWVTV3ZGZKYWhWZGd" +
	"3UGdTN1JRIiwgImNvdW50cnkiLCAiS2luZ2RvbSBvZiBcdTAwYzZuZGdhcmQiXQ~WyJIYlE0WDhzclZXM1FEeG5JSmRxeU9B" +
	"IiwgInBsYWNlX29mX2JpcnRoIiwgeyJfc2QiOiBbIkpET1lLUzB3MENvZm8tSGpaR3ZyZDdIaXJwU2ZpWURBTFU2cjhUX0xF" +
	"MWciLCAib1RacjlFbXk5eG1ycGNmUTVaU1U4c3Z4ZE1ZOHk0WElGXzVqOVAxdTF5QSJdfV0~WyJDOUdTb3VqdmlKcXVFZ1lm" +
	"b2pDYjFBIiwgIjEyIiwgdHJ1ZV0~WyJreDVrRjE3Vi14MEptd1V4OXZndnR3IiwgIjE0IiwgdHJ1ZV0~WyJIM28xdXN3UDc2" +
	"MEZpMnllR2RWQ0VRIiwgIjE2IiwgdHJ1ZV0~WyJPQktsVFZsdkxnLUFkd3FZR2JQOFpBIiwgIjE4IiwgdHJ1ZV0~WyJNMEpi" +
	"NTd0NDF1YnJrU3V5ckRUM3hBIiwgIjIxIiwgdHJ1ZV0~WyJEc210S05ncFY0ZEFIcGpyY2Fvc0F3IiwgIjY1IiwgZmFsc2Vd" +
	"~WyJlSzVvNXBIZmd1cFBwbHRqMXFoQUp3IiwgImFnZV9lcXVhbF9vcl9vdmVyIiwgeyJfc2QiOiBbIjF0RWl5elBSWU9Lc2Y" +
	"3U3NZR01nUFpLc09UMWxRWlJ4SFhBMHI1X0J3a2siLCAiQ1ZLbmx5NVA5MHlKczNFd3R4UWlPdFVjemFYQ1lOQTRJY3pSYW9" +
	"ock1EZyIsICJhNDQtZzJHcjhfM0FtSncyWFo4a0kxeTBRel96ZTlpT2NXMlczUkxwWEdnIiwgImdrdnkwRnV2QkJ2ajBoczJ" +
	"aTnd4Y3FPbGY4bXUyLWtDRTctTmIyUXh1QlUiLCAiaHJZNEhubUY1YjVKd0M5ZVR6YUZDVWNlSVFBYUlkaHJxVVhRTkNXYmZ" +
	"aSSIsICJ5NlNGclZGUnlxNTBJYlJKdmlUWnFxalFXejB0TGl1Q21NZU8wS3FhekdJIl19XQ~WyJqN0FEZGIwVVZiMExpMGNp" +
	"UGNQMGV3IiwgImFnZV9pbl95ZWFycyIsIDQ3XQ~WyJXcHhKckZ1WDh1U2kycDRodDA5anZ3IiwgImFnZV9iaXJ0aF95ZWFyI" +
	"iwgMTk3OF0~WyJhdFNtRkFDWU1iSlZLRDA1bzNKZ3RRIiwgInBvcnRyYWl0IiwgImRhdGE6aW1hZ2UvcG5nO2Jhc2U2NCxpV" +
	"kJPUncwS0dnb0FBQUFOU1VoRVVnQUFBQ1FBQUFBV0FRTUFBQUNTZkt4OUFBQUFBWE5TUjBJQjJja3Nmd0FBQUFSblFVMUJBQ" +
	"UN4and2OFlRVUFBQUFnWTBoU1RRQUFlaVlBQUlDRUFBRDZBQUFBZ09nQUFIVXdBQURxWUFBQU9wZ0FBQmR3bkxwUlBBQUFBQ" +
	"VpRVEZSRkFBQUEvLy8vcGRtZjNRQUFBRkZKUkVGVUNOZE55bEVOZ0RBUUE5QVNCSnlFV2NEQkxFMENUcERDcENEaFB2ZXhyQ" +
	"ndsQy95OE5HM1JNdW53OUFpNXA2L3ByL1p6bGNBaTRXaVJOMW5sWEFlc09naGVCVFNPOEpEbk5ENlozVytkOTBmQ25UampLU" +
	"UFBQUFCSlJVNUVya0pnZ2c9PSJd~WyI0S3lSMzJvSVp0LXprV3ZGcWJVTEtnIiwgImlzc3VhbmNlX2RhdGUiLCAiMjAyNC0w" +
	"MS0xNSJd~WyJjaEJDc3loeWgtSjg2SS1hd1FEaUNRIiwgImV4cGlyeV9kYXRlIiwgIjIwMzQtMDEtMTUiXQ~WyJmbE5QMW5j" +
	"TXo5TGctYzlxTUl6XzlnIiwgImlzc3VpbmdfYXV0aG9yaXR5IiwgIktpbmdkb20gb2YgXHUwMGM2bmRnYXJkLCBNaW5pc3Ry" +
	"eSBvZiBJbnRlcmlvciJd~WyJvdm9WMXJraF9BTm04NjFxVUFBMkF3IiwgImlzc3VpbmdfY291bnRyeSIsICJcdTAwYzZHIl0" +
	"~"

// RFC 9901 §4.2.6 and §7.2: only what reveal names and its concealed
// ancestors, each once, in the order issued (this SDK's order; §4 sets none).
func TestPresentDraft19Example(t *testing.T) {
	parts := strings.Split(draft19A1Issued, "~")
	jwt, d18, dAge := parts[0], parts[18], parts[21]
	for _, tc := range []struct {
		name   string
		reveal []sdjwt.Path
		want   string
	}{
		{"nothing named", nil, jwt + "~"},
		{"a claim without its concealed members", []sdjwt.Path{{"age_equal_or_over"}}, jwt + "~" + dAge + "~"},
		{"a member and its parent", []sdjwt.Path{{"age_equal_or_over"}, {"age_equal_or_over", "18"}}, jwt + "~" + d18 + "~" + dAge + "~"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Present(draft19A1Issued, tc.reveal, nil)
			if err != nil || got != tc.want {
				t.Fatalf("got %q, %v\nwant %q", got, err, tc.want)
			}
		})
	}
}

// Issue binds a P-256 holder key; Present with Key Binding; then what a
// verifier does: Split, Recreate and VerifyKBJWT with sd_hash over the
// presented SD-JWT (RFC 9901 §4.3.1). The result, an SD-JWT+KB, is refused as
// input (§7.2).
func TestPresentKeyBinding(t *testing.T) {
	req, key := testRequest(t)
	holderPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	req.HolderKey = &holderPriv.PublicKey
	req.Disclose = []sdjwt.Path{{"given_name"}, {"address"}, {"address", "locality"}, {"nationalities", 0}}
	issued, err := Issue(req, key)
	if err != nil {
		t.Fatal(err)
	}
	kb := &KeyBinding{Signer: memSigner{holderPriv}, Audience: "https://verifier.example", Nonce: "n-0S6_WzA2Mj", IssuedAt: time.Unix(1700000500, 0)}
	presented, err := Present(issued, []sdjwt.Path{{"address", "locality"}}, kb)
	if err != nil {
		t.Fatal(err)
	}

	issuerJWT, encoded, kbJWT, err := sdjwt.Split(presented)
	if err != nil || kbJWT == "" {
		t.Fatalf("Split: %v, KB-JWT %q", err, kbJWT)
	}
	want := sdjwt.KBWant{Audience: kb.Audience, Nonce: kb.Nonce, SDHash: sdjwt.SDHash(strings.TrimSuffix(presented, kbJWT)), Now: kb.IssuedAt}
	if _, err := sdjwt.VerifyKBJWT(kbJWT, &holderPriv.PublicKey, want); err != nil {
		t.Fatalf("VerifyKBJWT: %v", err)
	}
	_, body, err := jws.Verify(issuerJWT, key.Public, nil)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := jose.DecodeJSONObject(body)
	if err != nil {
		t.Fatal(err)
	}
	disclosures := make([]sdjwt.Disclosure, len(encoded))
	for i, e := range encoded {
		disclosures[i] = sdjwt.Disclosure{Encoded: e}
	}
	r, err := sdjwt.Recreate(payload, disclosures)
	if err != nil {
		t.Fatal(err)
	}
	// address and its locality; not given_name, nor nationalities[0].
	if len(encoded) != 2 || r.Claims["given_name"] != nil ||
		encodeJSON(t, r.Claims["address"]) != `{"country":"VN","locality":"Hanoi"}` ||
		encodeJSON(t, r.Claims["nationalities"]) != `["FR"]` {
		t.Errorf("verifier sees %d disclosures and %s", len(encoded), encodeJSON(t, r.Claims))
	}

	if got, err := Present(presented, nil, nil); got != "" || !errors.Is(err, jose.ErrMalformed) {
		t.Fatalf("SD-JWT+KB as input: %q, %v; want jose.ErrMalformed", got, err)
	}
}

// Key Binding is made only with the key the credential binds
// (draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.3), and never from a cnf that does not
// hold one.
func TestPresentRefusesKeyBinding(t *testing.T) {
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kb := &KeyBinding{Signer: memSigner{other}, Audience: "https://verifier.example", Nonce: "n", IssuedAt: time.Unix(1700000500, 0)}

	req, key := testRequest(t)
	req.HolderKey = nil
	unbound, err := Issue(req, key)
	if err != nil {
		t.Fatal(err)
	}
	// Present does not verify the Issuer's signature, so a made-up one does.
	withCnf := func(cnf string) string {
		return "eyJhbGciOiJFUzI1NiJ9." + jose.EncodeSegment([]byte(`{"cnf":`+cnf+`}`)) + ".c2ln~"
	}

	// draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.3: cnf MUST NOT be in a Disclosure.
	// The concealed key is the signer's, so binding to it would succeed.
	otherJWK, err := jwk.FromPublicKey(&other.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	payload, ds, err := sdjwt.Conceal(map[string]any{"cnf": map[string]any{"jwk": otherJWK}}, []sdjwt.Path{{"cnf"}}, sdjwt.ConcealOptions{})
	if err != nil {
		t.Fatal(err)
	}
	concealedCnf := "eyJhbGciOiJFUzI1NiJ9." + jose.EncodeSegment([]byte(encodeJSON(t, payload))) + ".c2ln~" + ds[0].Encoded + "~"
	// The same for cnf.jwk alone, a sub-claim, beside a plain kid.
	payload, ds, err = sdjwt.Conceal(map[string]any{"cnf": map[string]any{"kid": "x", "jwk": otherJWK}}, []sdjwt.Path{{"cnf", "jwk"}}, sdjwt.ConcealOptions{})
	if err != nil {
		t.Fatal(err)
	}
	concealedJWK := "eyJhbGciOiJFUzI1NiJ9." + jose.EncodeSegment([]byte(encodeJSON(t, payload))) + ".c2ln~" + ds[0].Encoded + "~"

	// Each refusal matches exactly one class, plus the cause in also; only a
	// broken key matches jwk.ErrBadKey.
	classes := []error{jose.ErrInvalidArgument, ErrKeyBindingUnsupported, jose.ErrMalformed}
	for _, tc := range []struct {
		name   string
		issued string
		class  error // nil: none of the classes
		also   error
	}{
		// The draft's holder key is in cnf.jwk; other holds another one.
		{"signer of another key", draft19A1Issued, nil, jws.ErrSelfCheck},
		{"no cnf", unbound, jose.ErrInvalidArgument, nil},
		{"cnf in a Disclosure", concealedCnf, jose.ErrMalformed, nil},
		{"cnf.jwk in a Disclosure", concealedJWK, jose.ErrMalformed, nil},
		// RFC 7800 §3.1: one proof-of-possession key, so one of jwk, jwe and
		// jku. The jwk is the signer's, so binding to it would succeed.
		{"cnf with jwk and jku", withCnf(`{"jwk":` + encodeJSON(t, otherJWK) + `,"jku":"https://issuer.example/jwks"}`), jose.ErrMalformed, nil},
		// RFC 7800 §3.4: cnf may name the key by kid alone.
		{"cnf without jwk", withCnf(`{"kid":"x"}`), ErrKeyBindingUnsupported, nil},
		// RFC 7800 §3.2 allows any asymmetric public JWK; this SDK binds EC only.
		{"cnf.jwk OKP", withCnf(`{"jwk":{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}}`), ErrKeyBindingUnsupported, jwk.ErrUnsupportedKey},
		// RFC 7800 §3.2: a symmetric jwk only in an encrypted JWT.
		{"cnf.jwk oct", withCnf(`{"jwk":{"kty":"oct","k":"AAAA"}}`), jose.ErrMalformed, jwk.ErrBadKey},
		// RFC 7518 §6.2.1: an EC public key on P-256 MUST have y.
		{"cnf.jwk EC without y", withCnf(`{"jwk":{"kty":"EC","crv":"P-256","x":"TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc"}}`), jose.ErrMalformed, jwk.ErrBadKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Present(tc.issued, nil, kb)
			if got != "" || err == nil {
				t.Fatalf("got %q, %v; want an error", got, err)
			}
			for _, c := range classes {
				if errors.Is(err, c) != (c == tc.class) {
					t.Errorf("got %v; errors.Is %v = %v, want %v", err, c, !(c == tc.class), c == tc.class)
				}
			}
			if tc.also != nil && !errors.Is(err, tc.also) {
				t.Errorf("got %v, want %v too", err, tc.also)
			}
			if bad := tc.also == jwk.ErrBadKey; errors.Is(err, jwk.ErrBadKey) != bad {
				t.Errorf("got %v; errors.Is jwk.ErrBadKey = %v, want %v", err, !bad, bad)
			}
		})
	}
}
