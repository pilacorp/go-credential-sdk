// The options of Credential.Verify. Each sets what the standards leave to the
// Verifier; when one is not passed, Verify follows the standard's rule where
// it sets one and otherwise the SDK default its godoc names, which never
// accepts what the standard rejects.

package dc

import (
	"fmt"
	"slices"
	"time"

	"github.com/pilacorp/go-credential-sdk/jose"
)

// VerifyOption sets one choice of Credential.Verify; the With functions of
// this package make them. Each option may be passed once per call: a second
// one is ErrPolicy, never "last one wins". An option holds no state, so one
// value can be reused across calls and goroutines.
type VerifyOption interface {
	setOn(c *verifyConfig) error
}

// option is every VerifyOption: name is the With function, for the error
// texts and the duplicate check, and set applies it.
type option struct {
	name string
	set  func(c *verifyConfig) error
}

func (o option) setOn(c *verifyConfig) error {
	if c.seen[o.name] {
		return policyErr("%s is passed more than once; pass each option once", o.name)
	}
	c.seen[o.name] = true
	return o.set(c)
}

// supportedAlgs are the algorithms jws verifies with; the default of
// WithAllowedAlgs.
var supportedAlgs = []string{"ES256", "ES256K"}

// SDK defaults for the window RFC 9901 §7.3 step 5e leaves to the Verifier
// (WithMaxKBAge) and the leeway RFC 7519 §4.1.4-4.1.5 allows (WithClockSkew).
const (
	defaultMaxKBAge  = 5 * time.Minute
	defaultClockSkew = time.Minute
)

// verifyConfig is what one call of Verify checks against: the defaults, then
// the options in the order passed.
type verifyConfig struct {
	algs              []string
	keyBinding        KeyBindingMode
	ignoreUncheckedKB bool
	audience, nonce   string
	credAudience      string
	maxKBAge, skew    time.Duration
	status            StatusChecker
	skipStatus        bool
	accepted          []uint8
	now               time.Time
	seen              map[string]bool
}

// newVerifyConfig builds the configuration of one call from opts. Its errors
// are all ErrPolicy, naming the option.
func newVerifyConfig(opts []VerifyOption) (verifyConfig, error) {
	c := verifyConfig{
		algs:     supportedAlgs,
		maxKBAge: defaultMaxKBAge,
		skew:     defaultClockSkew,
		accepted: []uint8{0x00},
		seen:     map[string]bool{},
	}
	for i, o := range opts {
		if o == nil {
			return verifyConfig{}, policyErr("option %d is nil", i)
		}
		if err := o.setOn(&c); err != nil {
			return verifyConfig{}, err
		}
	}
	if c.seen["WithStatus"] && c.seen["WithoutStatusCheck"] {
		return verifyConfig{}, policyErr("WithStatus and WithoutStatusCheck are both passed; pass one")
	}
	if c.keyBinding == KeyBindingRequired && (c.audience == "" || c.nonce == "") {
		return verifyConfig{}, policyErr("WithKeyBinding(KeyBindingRequired) needs WithAudience and WithNonce, which every Key Binding JWT is checked against (RFC 9901 §7.3 step 5f)")
	}
	if c.now.IsZero() {
		c.now = time.Now()
	}
	return c, nil
}

// WithAllowedAlgs lists the algorithms accepted for the Issuer-signed JWT and
// the Key Binding JWT (RFC 8725 §3.1; RFC 9901 §7.1 step 2a, §7.3 step 5b).
// Not passed, ES256 and ES256K are. No alg, or one other than these two, is
// ErrPolicy, the second also jose.ErrUnsupportedAlg. It does not reach the
// Status List Token: statuslist.Config.AllowedAlgs sets that. algs is copied.
func WithAllowedAlgs(algs ...string) VerifyOption {
	algs = slices.Clone(algs)
	return option{"WithAllowedAlgs", func(c *verifyConfig) error {
		if len(algs) == 0 {
			return policyErr("WithAllowedAlgs needs at least one alg")
		}
		for _, a := range algs {
			if !slices.Contains(supportedAlgs, a) {
				return fmt.Errorf("%w: dc: WithAllowedAlgs: %w: %q; this SDK verifies ES256 and ES256K", ErrPolicy, jose.ErrUnsupportedAlg, a)
			}
		}
		c.algs = algs
		return nil
	}}
}

// WithKeyBinding sets when Key Binding is required (RFC 9901 §7.3 step 1);
// not passed, KeyBindingIfCnf. A value that is none of the three modes is
// ErrPolicy, and so is KeyBindingRequired without WithAudience and WithNonce.
func WithKeyBinding(m KeyBindingMode) VerifyOption {
	return option{"WithKeyBinding", func(c *verifyConfig) error {
		switch m {
		case KeyBindingIfCnf, KeyBindingRequired, KeyBindingNotRequired:
			c.keyBinding = m
			return nil
		}
		return policyErr("WithKeyBinding(%d) is none of KeyBindingIfCnf, KeyBindingRequired and KeyBindingNotRequired", m)
	}}
}

// WithIgnoreUncheckedKBJWT accepts a Key Binding JWT that Verify does not
// check, because Key Binding is not required, and ignores it: KeyBound stays
// false and KeyBindingClaims nil. Not passed, such a Key Binding JWT is
// KB_UNEXPECTED, since a Holder (RFC 9901 §7.2) or a verifier expecting an
// SD-JWT (§4) MUST reject it. An OpenID4VP Verifier whose query sets
// require_cryptographic_holder_binding false may receive either form
// (OpenID4VP 1.0 Appendix B.3), and passes it with KeyBindingNotRequired.
func WithIgnoreUncheckedKBJWT() VerifyOption {
	return option{"WithIgnoreUncheckedKBJWT", func(c *verifyConfig) error {
		c.ignoreUncheckedKB = true
		return nil
	}}
}

// WithAudience is the aud this Verifier expects in the Key Binding JWT (RFC
// 9901 §7.3 step 5f), compared byte for byte. Needed whenever a Key Binding
// JWT is checked; without it that is ErrPolicy.
func WithAudience(aud string) VerifyOption {
	return option{"WithAudience", func(c *verifyConfig) error {
		c.audience = aud
		return nil
	}}
}

// WithNonce is the nonce of this transaction, which the Key Binding JWT must
// carry (RFC 9901 §7.3 step 5f), compared byte for byte. Needed whenever a Key
// Binding JWT is checked; without it that is ErrPolicy. Verify keeps no
// state: issuing a fresh nonce per transaction and accepting it once, the
// replay check of step 5f, is the caller's.
func WithNonce(nonce string) VerifyOption {
	return option{"WithNonce", func(c *verifyConfig) error {
		c.nonce = nonce
		return nil
	}}
}

// WithCredentialAudience is how this Verifier names itself in the
// Issuer-signed JWT's aud (RFC 7519 §4.1.3), read only when the credential
// has aud. Not passed, a credential with aud is AUDIENCE_MISMATCH. An aud the
// Issuer concealed and the Holder withheld is absent, which Verify cannot
// tell apart.
func WithCredentialAudience(aud string) VerifyOption {
	return option{"WithCredentialAudience", func(c *verifyConfig) error {
		c.credAudience = aud
		return nil
	}}
}

// WithMaxKBAge is how old the Key Binding JWT iat may be (RFC 9901 §7.3 step
// 5e, which leaves the window to the Verifier); not passed, 5 minutes. A
// value that is not positive is ErrPolicy.
func WithMaxKBAge(d time.Duration) VerifyOption {
	return option{"WithMaxKBAge", func(c *verifyConfig) error {
		if d <= 0 {
			return policyErr("WithMaxKBAge(%v) is not positive", d)
		}
		c.maxKBAge = d
		return nil
	}}
}

// WithClockSkew is the leeway on exp and nbf of the credential and the Key
// Binding JWT (RFC 7519 §4.1.4, §4.1.5: a small leeway MAY be allowed) and on
// the Key Binding JWT iat; not passed, 1 minute. 0 allows no skew; a negative
// value is ErrPolicy.
func WithClockSkew(d time.Duration) VerifyOption {
	return option{"WithClockSkew", func(c *verifyConfig) error {
		if d < 0 {
			return policyErr("WithClockSkew(%v) is negative", d)
		}
		c.skew = d
		return nil
	}}
}

// WithStatus is the StatusChecker for a credential with status_list
// (draft-ietf-oauth-status-list-21 §8.3), such as a *statuslist.Checker. Not
// passed, such a credential is ErrPolicy, unless WithoutStatusCheck is, so
// that a forgotten checker never accepts a revoked credential. nil is
// ErrPolicy; a typed nil of the caller's own type cannot be detected.
func WithStatus(s StatusChecker) VerifyOption {
	return option{"WithStatus", func(c *verifyConfig) error {
		if s == nil {
			return policyErr("WithStatus(nil); pass a StatusChecker such as a *statuslist.Checker")
		}
		c.status = s
		return nil
	}}
}

// WithoutStatusCheck accepts a credential with status without checking it,
// and Result.StatusSkipped says so. draft-ietf-oauth-sd-jwt-vc-19 §2.4 says
// the status SHOULD be checked; this option skips that SHOULD for a Verifier
// whose policy does not use it. The shape of status is checked anyway.
// Passing it with WithStatus is ErrPolicy.
func WithoutStatusCheck() VerifyOption {
	return option{"WithoutStatusCheck", func(c *verifyConfig) error {
		c.skipStatus = true
		return nil
	}}
}

// WithAcceptedStatus lists the status values accepted; not passed, only 0x00,
// VALID (draft-ietf-oauth-status-list-21 §7.1). No value is ErrPolicy. v is
// copied.
func WithAcceptedStatus(v ...uint8) VerifyOption {
	v = slices.Clone(v)
	return option{"WithAcceptedStatus", func(c *verifyConfig) error {
		if len(v) == 0 {
			return policyErr("WithAcceptedStatus needs at least one value")
		}
		c.accepted = v
		return nil
	}}
}

// WithNow is the time of the check, for exp, nbf and the Key Binding JWT
// alike; not passed, time.Now() read once. It does not reach the
// StatusChecker, which checks the Status List Token with its own clock. The
// zero time is ErrPolicy.
func WithNow(t time.Time) VerifyOption {
	return option{"WithNow", func(c *verifyConfig) error {
		if t.IsZero() {
			return policyErr("WithNow(time.Time{}); pass the time of the check")
		}
		c.now = t
		return nil
	}}
}

// policyErr is ErrPolicy with the fix; a cause goes in with %v, so the error
// matches no other sentinel.
func policyErr(format string, a ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrPolicy}, a...)...)
}
