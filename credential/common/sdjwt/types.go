package sdjwt

// ParsedSDJWT represents a parsed SD-JWT at the string level.
type ParsedSDJWT struct {
	BaseJWT            string              // issuer-signed JWT (before first '~')
	Disclosures        []string            // disclosure strings between '~' (base64url(JSON array))
	DecodedDisclosures []DecodedDisclosure // parsed disclosures with metadata (useful for Holders)
}

// TargetKind represents the type of disclosure target.
//
// Deprecated: nothing in the SDK uses it since BuildDisclosures runs on
// jose/sdjwt; it will be removed in a future release.
type TargetKind int

const (
	TargetKindObjectField    TargetKind = iota // object field (e.g., "name")
	TargetKindArrayContainer                   // array field (e.g., "emails" as whole array)
	TargetKindArrayElem                        // array element (e.g., "emails[0]")
)

// String returns the string representation of TargetKind.
func (k TargetKind) String() string {
	switch k {
	case TargetKindObjectField:
		return "objectField"
	case TargetKindArrayContainer:
		return "arrayContainer"
	case TargetKindArrayElem:
		return "arrayElem"
	default:
		return "unknown"
	}
}
