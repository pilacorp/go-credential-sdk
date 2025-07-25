package vc

func mapSlice[T any, U any](slice []T, mapFN func(T) U) []U {
	var result []U
	for _, v := range slice {
		result = append(result, mapFN(v))
	}

	return result
}
