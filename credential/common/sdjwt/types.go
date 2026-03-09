package sdjwt

// ParsedSDJWT represents a parsed SD-JWT at the string level.
type ParsedSDJWT struct {
	BaseJWT            string              // issuer-signed JWT (before first '~')
	Disclosures        []string            // disclosure strings between '~' (base64url(JSON array))
	DecodedDisclosures []DecodedDisclosure // parsed disclosures with metadata (useful for Holders)
}

// TargetKind represents the type of disclosure target.
type TargetKind int

const (
	TargetKindObjectField    TargetKind = iota // object field (e.g., "name")
	TargetKindArrayContainer                   // array field (e.g., "emails" as whole array)
	TargetKindArrayElem                       // array element (e.g., "emails[0]")
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

// pathSegment represents one step in a dot/[index] path.
type pathSegment struct {
	key   string // the key of the object field or the index of the array element
	index *int   // the index of the array element if the path is an array element
}

// disclosureInfo holds parsed disclosure metadata used during reconstruction.
type disclosureInfo struct {
	raw         string
	salt        string
	array       []interface{}
	objectField string
	value       interface{}
	isArrayElem bool
}

// resolvedTarget holds the result of resolvePath.
type resolvedTarget struct {
	parent    interface{}  // The parent container (map or array)
	parentMap *map[string]interface{} // Reference to parent map for write-back
	parentKey string      // Key name in parent map (for write-back)
	kind      TargetKind  // Type of target
	fieldName string      // Key name (for object fields)
	index     int         // Array index (for array elements)
	value     interface{} // The actual value at this location
}
