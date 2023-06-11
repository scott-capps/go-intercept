package policy

import (
	"fmt"
	"net/http"
)

type CookieErrorPolicy struct {
	ErrorIfMissing bool // Whether to return an error if a cookie is missing
	ErrorIfEmpty   bool // Whether to return an error if a cookie is empty
}

type CookieParserPolicy struct {
	Required []string      // Required cookies
	MaxAge   int           // Maximum allowed age
	Secure   bool          // Whether cookies must be secure
	HttpOnly bool          // Whether cookies must be HTTP only
	SameSite http.SameSite // Required SameSite attribute
	// CookiesToParse lists the names of cookies that should be parsed.
	CookiesToParse []string
	// ErrorHandler defines a function that will handle errors that occur during cookie parsing.
	ErrorHandler func(err error)
	// MissingCookieHandler defines a function that will handle cases where a cookie is expected but not found.
	MissingCookieHandler func(cookieName string)
	// InvalidCookieHandler defines a function that will handle cases where a cookie is found but is not valid.
	InvalidCookieHandler func(cookieName string, cookie *http.Cookie)
	// ValidCookieHandler defines a function that will handle cases where a cookie is found and is valid.
	ValidCookieHandler func(cookieName string, cookie *http.Cookie)
	ErrorPolicy        CookieErrorPolicy
}

func (crs CookieParserPolicy) ValidateCookie(cookie *http.Cookie) error {
	// Check if the cookie is in the required list
	if contains(crs.Required, cookie.Name) && crs.ErrorPolicy.ErrorIfMissing {
		return fmt.Errorf("cookie %s is missing", cookie.Name)
	}

	// Check the maximum age
	if cookie.MaxAge > crs.MaxAge {
		return fmt.Errorf("cookie %s exceeds the maximum age", cookie.Name)
	}

	// Check if the cookie must be secure
	if crs.Secure && !cookie.Secure {
		return fmt.Errorf("cookie %s is not secure", cookie.Name)
	}

	// Check if the cookie must be HTTP only
	if crs.HttpOnly && !cookie.HttpOnly {
		return fmt.Errorf("cookie %s is not HTTP only", cookie.Name)
	}

	// Check the SameSite attribute
	if crs.SameSite != cookie.SameSite {
		return fmt.Errorf("cookie %s does not have the required SameSite attribute", cookie.Name)
	}

	// Check if the cookie value is empty
	if cookie.Value == "" && crs.ErrorPolicy.ErrorIfEmpty {
		return fmt.Errorf("cookie %s is empty", cookie.Name)
	}

	// If the cookie passes all checks, return nil (no error)
	return nil
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
