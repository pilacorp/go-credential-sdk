package ecdsasd

// deepCopy returns a deep copy of a JSON-like value (maps, slices, scalars).
func deepCopy(v interface{}) interface{} {
	switch t := v.(type) {
	case map[string]interface{}:
		return deepCopyMap(t)
	case []interface{}:
		out := make([]interface{}, len(t))
		for i := range t {
			out[i] = deepCopy(t[i])
		}
		return out
	default:
		return t
	}
}

func deepCopyMap(m map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		out[k] = deepCopy(v)
	}
	return out
}
