package dto

import "encoding/json"

// Proof represents a Linked Data Proof for a Verifiable Credential.
//
// The typed fields cover the full property set of W3C Data Integrity 1.0
// § 2.1. Any other property is kept in Extra so that a proof round-trips
// unchanged through parse and serialize: § 4.4 hashes the whole proof object
// minus proofValue, so dropping a property the SDK does not model would break
// the signature of proofs issued by other implementations.
type Proof struct {
	// Data Integrity 1.0 § 2.1 properties.
	Id                 string          `json:"id,omitempty"`
	Type               string          `json:"type,omitempty"`
	Created            string          `json:"created,omitempty"`
	Expires            string          `json:"expires,omitempty"`
	VerificationMethod string          `json:"verificationMethod,omitempty"`
	ProofPurpose       string          `json:"proofPurpose,omitempty"`
	Cryptosuite        string          `json:"cryptosuite,omitempty"`
	Challenge          string          `json:"challenge,omitempty"`
	Domain             string          `json:"domain,omitempty"`
	Nonce              string          `json:"nonce,omitempty"`
	PreviousProof      StringOrStrings `json:"previousProof,omitempty"`
	ProofValue         string          `json:"proofValue,omitempty"`

	// JWS is the detached JWS a JsonWebSignature2020 proof carries instead of
	// proofValue.
	JWS string `json:"jws,omitempty"`
	// Signature carries the raw signature for the JWT external signing
	// workflow (AddCustomProof). Never serialized into a proof object.
	Signature []byte `json:"-"`

	// Extra keeps every other proof property so it survives parse and
	// serialize; a set typed field wins over the same key here.
	Extra map[string]interface{} `json:"-"`
}

// StringOrStrings is the "string or set of strings" value shape § 2.1 allows
// for previousProof. A single value round-trips as a plain string.
type StringOrStrings []string

func (s *StringOrStrings) UnmarshalJSON(data []byte) error {
	var one string
	if json.Unmarshal(data, &one) == nil {
		*s = StringOrStrings{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return err
	}
	*s = many
	return nil
}

func (s StringOrStrings) MarshalJSON() ([]byte, error) {
	if len(s) == 1 {
		return json.Marshal(s[0])
	}
	return json.Marshal([]string(s))
}

// ProofFromMap builds a Proof from a JSON proof object. A property lands in
// its typed field when the value fits the field's JSON tag, otherwise in Extra.
func ProofFromMap(m map[string]interface{}) Proof {
	var p Proof
	raw, _ := json.Marshal(m)
	_ = json.Unmarshal(raw, &p) // a mismatched value is skipped, not fatal

	typed := p.ToMap()
	for key, value := range m {
		if _, ok := typed[key]; ok {
			continue
		}
		if p.Extra == nil {
			p.Extra = make(map[string]interface{})
		}
		p.Extra[key] = value
	}
	return p
}

// ToMap serializes the proof as a JSON proof object: Extra first, then every
// non-empty typed field on top.
func (p Proof) ToMap() map[string]interface{} {
	out := make(map[string]interface{}, len(p.Extra)+12)
	for key, value := range p.Extra {
		out[key] = value
	}

	var typed map[string]interface{}
	raw, _ := json.Marshal(p)
	_ = json.Unmarshal(raw, &typed)
	for key, value := range typed {
		out[key] = value
	}
	return out
}
