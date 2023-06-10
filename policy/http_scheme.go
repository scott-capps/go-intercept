package policy

type HttpSchemePolicy struct {
	Http  bool
	Https bool
}

// isSchemeAllowed checks if a scheme is in the list of allowed schemes.
// It returns true if the scheme is allowed and false otherwise.
func IsSchemeAllowed(scheme string, allowedSchemes []string) bool {
	for _, allowed := range allowedSchemes {
		if scheme == allowed {
			// If the scheme is in the list of allowed schemes, return true.
			return true
		}
	}
	// If we get through the entire list without finding the scheme, return false.
	return false
}
