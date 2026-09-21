package vc

import "fmt"

// DataModel selects which W3C Verifiable Credentials Data Model a credential is
// built against. The two differ in the base @context and in what the validity
// period properties are called, so the choice has to be made when the document
// is built — not when it is signed, by which point the document is closed.
type DataModel int

const (
	// DataModelUnset is the zero value: the caller expressed no preference.
	// It writes a 2.0 document — credentials/v2, validFrom / validUntil — but
	// takes a caller-supplied @context exactly as given, whatever it names.
	// This is what every existing caller gets, so their documents are
	// unchanged.
	DataModelUnset DataModel = iota

	// DataModel20 is VC Data Model 2.0, chosen explicitly: credentials/v2,
	// validFrom / validUntil, and a caller-supplied @context must agree.
	DataModel20

	// DataModel11 is VC Data Model 1.1: credentials/v1, issuanceDate /
	// expirationDate. Needed for the EcdsaSecp256k1Signature2019 proof suite,
	// which 2.0 does not cover.
	DataModel11
)

const (
	credentialsV1Context = "https://www.w3.org/2018/credentials/v1"
	credentialsV2Context = "https://www.w3.org/ns/credentials/v2"
)

// baseContext is the @context URL the data model requires as its first value.
func (m DataModel) baseContext() string {
	if m == DataModel11 {
		return credentialsV1Context
	}
	return credentialsV2Context
}

// validityPropertyNames returns the property names carrying the validity
// period: (validFrom, validUntil) for 2.0, (issuanceDate, expirationDate) for
// 1.1.
func (m DataModel) validityPropertyNames() (string, string) {
	if m == DataModel11 {
		return "issuanceDate", "expirationDate"
	}
	return "validFrom", "validUntil"
}

func (m DataModel) String() string {
	if m == DataModel11 {
		return "VC Data Model 1.1"
	}
	return "VC Data Model 2.0"
}

// ContextForDataModel returns the @context to write, defaulting it to the data
// model's base context when the caller supplied none.
//
// A caller-supplied @context is never rewritten — swapping the base context
// under a document would leave the rest of it (credentialStatus.type,
// credentialSchema.type, and any 2.0-only property) declaring a data model the
// document no longer claims. When the caller chose a data model explicitly and
// the @context names the other one, that mismatch is reported instead.
//
// DataModelUnset skips the check entirely: callers who never asked for a data
// model keep whatever @context they have always passed.
func ContextForDataModel(ctx []interface{}, model DataModel) ([]interface{}, error) {
	if len(ctx) == 0 {
		return []interface{}{model.baseContext()}, nil
	}
	if model == DataModelUnset {
		return ctx, nil
	}

	first, ok := ctx[0].(string)
	if !ok {
		// An inline context object first: unusual, but the caller is driving.
		return ctx, nil
	}

	other := DataModel20
	if model == DataModel20 {
		other = DataModel11
	}
	if first == other.baseContext() {
		return nil, fmt.Errorf(
			"@context starts with %q but the credential is being built as %s; pass the matching base context %q, or drop @context to get it by default",
			first, model, model.baseContext())
	}

	return ctx, nil
}
