package sdjwt

// ParsedSDJWT represents a parsed SD-JWT at the string level.
type ParsedSDJWT struct {
	BaseJWT            string              // issuer-signed JWT (before first '~')
	Disclosures        []string            // disclosure strings between '~' (base64url(JSON array))
	DecodedDisclosures []DecodedDisclosure // parsed disclosures with metadata (useful for Holders)
}

// pathSegment represents one step in a dot/[index] path.
type pathSegment struct {
	key   string
	index *int
}

// disclosureInfo holds parsed disclosure metadata used during reconstruction.
type disclosureInfo struct {
	raw         string
	array       []interface{}
	objectField string
	value       interface{}
	isArrayElem bool
}
