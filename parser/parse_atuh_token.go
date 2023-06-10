package parser

import (
	"net/http"
	"strings"
)

/*
ParseAuthToken extracts the bearer token from an HTTP request.
The token, if present, is expected to be in the Authorization header
in the format "Bearer {token}".
*/
func ParseAuthToken(r *http.Request) string {
	// Get the Authorization header from the request
	authHeader := r.Header.Get("Authorization")

	// Check if the header is long enough to possibly contain a bearer token
	// and if the beginning of the header matches "bearer " case-insensitively
	if len(authHeader) > 6 && strings.ToLower(authHeader[0:7]) == "bearer " {
		// If it does, return everything after the first 7 characters,
		// which should be the bearer token itself
		return authHeader[7:]
	}

	// If the header isn't in the expected format, return an error
	return ""
}
