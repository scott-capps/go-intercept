package policy

import (
	"net/http"
	"strconv"
	"strings"
)

/*
CorsPolicy holds the configuration for Cross-Origin Resource Sharing (CORS).
CORS is a mechanism that uses additional HTTP headers to tell browsers
to give a web application running at one origin, access to selected resources
from a different origin.
*/
type CorsPolicy struct {
	AllowOrigin      string
	AllowMethods     []string
	AllowHeaders     []string
	AllowCredentials bool
	ExposeHeaders    []string
	MaxAge           int
}

/*
BuildCorsFromPolicy sets the HTTP headers on the ResponseWriter based on the provided CorsPolicy.
*/
func BuildCorsFromPolicy(policy CorsPolicy, w http.ResponseWriter) {

	// Set the Access-Control-Allow-Origin header to the value defined in the policy.
	// This header specifies which origins are allowed to access the resource over CORS.
	w.Header().Set("Access-Control-Allow-Origin", policy.AllowOrigin)

	// If there are any methods defined in the policy, join them with a comma and
	// set the Access-Control-Allow-Methods header. This header specifies the methods
	// allowed when accessing the resource.
	if len(policy.AllowMethods) > 0 {
		w.Header().Set("Access-Control-Allow-Methods", strings.Join(policy.AllowMethods, ", "))
	}

	// If there are any headers defined in the policy, join them with a comma and
	// set the Access-Control-Allow-Headers header. This header is used in response
	// to a preflight request to indicate which HTTP headers can be used when making
	// the actual request.
	if len(policy.AllowHeaders) > 0 {
		w.Header().Set("Access-Control-Allow-Headers", strings.Join(policy.AllowHeaders, ", "))
	}

	// If credentials are allowed according to the policy, set the
	// Access-Control-Allow-Credentials header to 'true'. This header tells browsers
	// whether to expose the response to frontend JavaScript code when the request's
	// credentials mode (Request.credentials) is 'include'.
	if policy.AllowCredentials {
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}

	// If there are any headers that should be exposed according to the policy, join
	// them with a comma and set the Access-Control-Expose-Headers header. This header
	// lets a server whitelist headers that browsers are allowed to access.
	if len(policy.ExposeHeaders) > 0 {
		w.Header().Set("Access-Control-Expose-Headers", strings.Join(policy.ExposeHeaders, ", "))
	}

	// Set the Access-Control-Max-Age header to the value defined in the policy.
	// This header indicates how long the results of a preflight request can be cached.
	// If MaxAge is not defined in the policy (i.e., MaxAge <= 0), default to 86400 seconds (24 hours).
	if policy.MaxAge > 0 {
		w.Header().Set("Access-Control-Max-Age", strconv.Itoa(policy.MaxAge))
	} else {
		w.Header().Set("Access-Control-Max-Age", "86400")
	}
}
