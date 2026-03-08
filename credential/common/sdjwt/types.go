package sdjwt

// ParsedSDJWT represents a parsed SD-JWT at the string level.
type ParsedSDJWT struct {
	BaseJWT            string              // issuer-signed JWT (before first '~')
	Disclosures        []string            // disclosure strings between '~' (base64url(JSON array))
	DecodedDisclosures []DecodedDisclosure // parsed disclosures with metadata (useful for Holders)
}

// pathSegment represents one step in a dot/[index] path.
type pathSegment struct {
	key   string // the key of the object field or the index of the array element
	index *int   // the index of the array element if the path is an array element
}

// disclosureInfo holds parsed disclosure metadata used during reconstruction.
type disclosureInfo struct {
	raw         string
	array       []interface{}
	objectField string
	value       interface{}
	isArrayElem bool
}

// resolvedTarget holds the result of resolveDisclosureTarget.
type resolvedTarget struct {
	parent    interface{}
	kind      string
	fieldName string
	index     int
	value     interface{}
}
