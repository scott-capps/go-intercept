package structs

import (
	"net/http"
	"time"
)

type CookieConfig struct {
	Name     string        // the name of the cookie.
	Value    string        // the value of the cookie.
	Path     string        // the URL path that must exist in the requested URL, or "/" (the default) if no value is provided.
	Domain   string        // the domain that will see the cookie. If not set, this defaults to the origin server.
	Expires  time.Time     // the maximum lifetime of the cookie as an HTTP-date timestamp.
	MaxAge   int           // the maximum amount of time in seconds that the cookie is valid for. Must be > 0.
	Secure   bool          // whether the cookie should only be sent over HTTPS.
	HttpOnly bool          // whether the cookie is only used in HTTP requests and is not accessible through JavaScript.
	SameSite http.SameSite // an enum that indicates a cookie ought not to be sent along with cross-site requests.
	Raw      string        // the raw text of the cookie.
	Unparsed []string      // Raw text of unparsed attribute-value pairs
}
