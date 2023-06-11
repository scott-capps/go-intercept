package intercept

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cappizzle/go-intercept/intercept/parser"
	"github.com/cappizzle/go-intercept/intercept/policy"
	"github.com/cappizzle/go-intercept/intercept/structs"
)

type Middleware func(http.Handler) http.Handler

// Interceptor acts as a builder for middleware, allowing middleware
// to be easily added and then finally building the final http.Handler.
type Interceptor struct {
	Middleware []Middleware
}

// NewInterceptor creates a new Interceptor.
func NewInterceptor() *Interceptor {
	return &Interceptor{}
}

// Use adds a Middleware to the chain.
func (interceptor *Interceptor) Use(m Middleware) *Interceptor {
	interceptor.Middleware = append(interceptor.Middleware, m)
	return interceptor
}

/*
WithCookie adds a middleware to the chain that sets a cookie in the HTTP response.

	Example:
	interceptor := intercept.NewInterceptor()

	cookieConfig := structs.CookieConfig {
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

	interceptor.WithCookie(cookieConfig)
*/
func (interceptor *Interceptor) WithCookie(config structs.CookieConfig) *Interceptor {
	// Create a middleware function that sets a cookie.
	interceptFunc := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Set the cookie in the HTTP response.
			http.SetCookie(w, &http.Cookie{
				Name:     config.Name,
				Value:    config.Value,
				Path:     config.Path,
				Domain:   config.Domain,
				Expires:  config.Expires,
				MaxAge:   config.MaxAge,
				Secure:   config.Secure,
				HttpOnly: config.HttpOnly,
				SameSite: config.SameSite,
				Raw:      config.Raw,
				Unparsed: config.Unparsed,
			})

			// Pass control to the next handler in the chain.
			next.ServeHTTP(w, r)
		})
	}

	// Add the middleware function to the chain.
	interceptor.Use(interceptFunc)
	return interceptor
}

/*
WithCookieParser adds a middleware to the chain that parses cookies from the HTTP request.

	Example:
	interceptor := intercept.NewInterceptor()

	policy := policy.CookieParserPolicy{
		Required: []string{"cookie1", "cookie2"},
		MaxAge:   86400,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		CookiesToParse: []string{"cookie1", "cookie2"},
		ErrorHandler: func(err error) {
			log.Println(err)
		}
		MissingCookieHandler: func(cookieName string) {
			log.Printf("cookie %s is missing", cookieName)
		}
		InvalidCookieHandler: func(cookieName string, cookie *http.Cookie) {
			log.Printf("cookie %s is invalid", cookieName)
		}
		ValidCookieHandler: func(cookieName string, cookie *http.Cookie) {
			log.Printf("cookie %s is valid", cookieName)
		}
		ErrorPolicy: policy.CookieErrorPolicy{
			ErrorIfMissing: true,
			ErrorIfEmpty:   true,
		}
	}

	interceptor.WithCookieParser(policy)
*/
func (interceptor *Interceptor) WithCookieParser(p policy.CookieParserPolicy) *Interceptor {
	// the middleware function that parses and validates cookies.
	interceptFunc := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Iterate through the list of cookies to parse.
			for _, cookieName := range p.CookiesToParse {
				// Try to get the cookie from the request.
				cookie, err := r.Cookie(cookieName)

				// If there's an error, handle it according to the error handling policy.
				if err != nil {
					// If the cookie doesn't exist, create a default cookie and add it to the response.
					if errors.Is(err, http.ErrNoCookie) {
						expiration := time.Now().Add(365 * 24 * time.Hour)
						cookie := http.Cookie{Name: cookieName, Value: "default", Expires: expiration}
						http.SetCookie(w, &cookie)
						continue
					} else if p.ErrorHandler != nil {
						// If there's an error handler, call it with the error.
						p.ErrorHandler(err)
					}
					continue
				}

				// Validate the cookie according to the cookie parsing policy.
				if err = p.ValidateCookie(cookie); err != nil {
					// If there's an invalid cookie handler, call it with the cookie.
					if p.InvalidCookieHandler != nil {
						p.InvalidCookieHandler(cookieName, cookie)
					}
					// Return an error to the client.
					http.Error(w, "error parsing cookie", http.StatusUnauthorized)
					return
				}

				// If there's a valid cookie handler, call it with the cookie.
				if p.ValidCookieHandler != nil {
					p.ValidCookieHandler(cookieName, cookie)
				}

				// Add the cookie to the request's context for use in downstream handlers.
				ctx := context.WithValue(r.Context(), cookieName, cookie)
				r = r.WithContext(ctx)
			}
			// Pass control to the next handler in the chain.
			next.ServeHTTP(w, r)
		})
	}

	// Add the intercept function to the interceptor's middleware chain.
	interceptor.Use(interceptFunc)
	return interceptor
}

/*
WithLimitedHTTPVerbs adds a middleware to the chain that restricts the HTTP methods as defined in the HttpVerbPolicy.

	Example:
	chain := middleware.NewMiddlewareChain()

	policy := policy.HttpVerbPolicy{
		Post    bool
		Patch   bool
		Put     bool
		Delete  bool
		Get     bool
		Head    bool
		Options bool
		Trace   bool
		Connect bool
	}

	chain.WithLimitedHTTPVerbs(policy)
*/
func (interceptor *Interceptor) WithLimitedHTTPVerbs(policy policy.HttpVerbPolicy) *Interceptor {
	mwFunc := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch true {
			case r.Method == http.MethodPost && !policy.Post:
				http.Error(w, "Invalid method", http.StatusMethodNotAllowed)
				return
			case r.Method == http.MethodPatch && !policy.Patch:
				http.Error(w, "Invalid method", http.StatusMethodNotAllowed)
				return
			case r.Method == http.MethodPut && !policy.Put:
				http.Error(w, "Invalid method", http.StatusMethodNotAllowed)
				return
			case r.Method == http.MethodDelete && !policy.Delete:
				http.Error(w, "Invalid method", http.StatusMethodNotAllowed)
				return
			case r.Method == http.MethodGet && !policy.Get:
				http.Error(w, "Invalid method", http.StatusMethodNotAllowed)
				return
			case r.Method == http.MethodHead && !policy.Head:
				http.Error(w, "Invalid method", http.StatusMethodNotAllowed)
				return
			case r.Method == http.MethodOptions && !policy.Options:
				http.Error(w, "Invalid method", http.StatusMethodNotAllowed)
				return
			case r.Method == http.MethodTrace && !policy.Trace:
				http.Error(w, "Invalid method", http.StatusMethodNotAllowed)
				return
			case r.Method == http.MethodConnect && !policy.Connect:
				http.Error(w, "Invalid method", http.StatusMethodNotAllowed)
				return
			}
			next.ServeHTTP(w, r)
		})
	}

	interceptor.Use(mwFunc)
	return interceptor
}

/*
WithMaxBody adds a middleware function to the chain that limits the size of the request body to maxSize bytes.
If a client sends a request with a body larger than maxSize, the server will respond with a "413 Request Entity Too Large" status.
This middleware is a recommended way to prevent clients from sending overly large request bodies to your server.

	Example:
	interceptor := middleware.NewMInterceptor()
	maxSize := int64(1024 * 1024) // 1 MB
	interceptor.WithMaxBody(maxSize)
*/
func (interceptor *Interceptor) WithMaxBody(maxSize int64) *Interceptor {
	// Define the middleware function.
	interceptorFunc := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Limit the size of the request body.
			r.Body = http.MaxBytesReader(w, r.Body, maxSize)

			// Attempt to read the entire body.
			body, err := ioutil.ReadAll(r.Body)
			if err != nil {
				// If the body is too large, respond with '413 Status Request Entity Too Large'.
				if err == http.ErrHandlerTimeout {
					http.Error(w, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
					return
				}

				// For other errors, respond with '500 Internal Server Error'.
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}

			r.Body = ioutil.NopCloser(bytes.NewBuffer(body))
			// Pass control to the next middleware function or the final handler.
			next.ServeHTTP(w, r)
		})
	}

	// Add the middleware function to the chain.
	interceptor.Use(interceptorFunc)

	// Return the MiddlewareChain to allow method chaining.
	return interceptor
}

/*
WithCors adds a Cross-Origin Resource Sharing (CORS) middleware to the MiddlewareChain.
The input is used to set the Access-Control-Allow-Origin header,
which determines which domains can access this resource.

	Example:
	interceptor := middleware.NewMInterceptor()
	cp := policy.CorsPolicy{
		AllowOrigin:      "https://example.com",
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE"},
	}
	interceptor.WithCors(cp)
*/
func (interceptor *Interceptor) WithCors(p policy.CorsPolicy) *Interceptor {
	// Define the middleware function.
	interceptorFunc := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			policy.BuildCorsFromPolicy(p, w)

			// If the HTTP request method is OPTIONS, then it is a CORS preflight request.
			// For such request, we just return without forwarding the request to the next handler in the chain.
			if r.Method == "OPTIONS" {
				return
			}

			// For other types of requests, pass the request to the next handler in the middleware chain.
			next.ServeHTTP(w, r)
		})
	}
	// Add the CORS middleware function to the MiddlewareChain and return the updated chain.
	interceptor.Use(interceptorFunc)
	return interceptor
}

/*
WithHeaderParser adds a middleware to parse http headers and apply them to context
so that the GrapgQL resolvers have access to the supplied header values.
This middleware can be used as such:

	interceptor := intercept.NewInterceptor()

	policies := []policy.HeaderPolicy{
		{
			Header:         "Authorization",
			ErrorOnMissing: true,
			ContextKey: "auth-token",
		},
	}

	interceptor.WithHeaderParser(policies)
*/
func (interceptor *Interceptor) WithHeaderParser(policies []policy.HeaderPolicy) *Interceptor {
	interceptorFunc := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			// Iterate through each header policy
			for _, policy := range policies {
				// Get the header from the request
				headerValue := r.Header.Get(policy.Header)

				// If the header is missing and the policy says to return an error,
				// return an error
				if headerValue == "" && policy.ErrorOnMissing {
					// Handle the error by writing an error message and returning.
					http.Error(w, "error reading http header", http.StatusUnauthorized)
					return
				}

				if strings.ToLower(policy.Header) == "authorization" {
					token := parser.ParseAuthToken(r)

					if len(token) == 0 {
						// Handle the error by writing an error message and returning.
						http.Error(w, "error reading auth token", http.StatusUnauthorized)
						return
					}

					// apply the bearer token to context so resolvers have access to the value
					ctx = context.WithValue(ctx, policy.ContextKey, token)
				} else {
					// apply the header value to context so resolvers have access to the value
					ctx = context.WithValue(ctx, policy.ContextKey, headerValue)
				}
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
	interceptor.Use(interceptorFunc)
	return interceptor
}

/*
WithAllowedSchemes is a middleware that restricts the URL schemes allowed by your application.
The allowed schemes are passed as a parameter when creating the middleware.
If an incoming request uses a scheme not in the allowed list, it will respond with a "403 Forbidden" status.
Otherwise, it will pass the request to the next middleware or handler.

	Example:
	interceptor := intercept.NewInterceptor()
	p := policy.HttpSchemePolicy{
		Http:  true,
		Https: true,
	}
	interceptor.WithAllowedSchemes(p)
*/
func (interceptor *Interceptor) WithAllowedSchemes(p policy.HttpSchemePolicy) *Interceptor {
	interceptorFunc := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Default to assuming the request scheme is http.
			scheme := "http"
			// If r.TLS is not nil, the request was made over HTTPS, so update the scheme.
			if r.TLS != nil {
				scheme = "https"
			}

			// Check if the scheme is in the list of allowed schemes. If not, respond with
			// a 403 Forbidden status and return, stopping further handling of the request.
			if (scheme == "http" && !p.Http) || (scheme == "https" && !p.Https) {
				http.Error(w, "URL scheme not allowed", http.StatusForbidden)
				return
			}

			// If the scheme is allowed, call the next middleware in the chain, or the final
			// handler if there are no more middleware. Pass along the original ResponseWriter
			// and the Request with the updated context.
			next.ServeHTTP(w, r)
		})
	}

	// Add the middleware function to the chain.
	interceptor.Use(interceptorFunc)
	return interceptor
}

/*
WithContentSecurityPolicyProtection receives a policy string and adds it to the HTTP response headers.
This allows the function to be more flexible and reusable with different policies.

	Example:
	interceptor := intercept.NewInterceptor()
	p := policy.ContentSecurityPolicy{
		DefaultSrc: []string{"'self'"},
		ScriptSrc:  []string{"'self'", "https://apis.google.com"},
		StyleSrc:   []string{"'self'", "https://fonts.googleapis.com"},
		ImgSrc:     []string{"'self'", "https://www.google-analytics.com"},
		FontSrc:    []string{"'self'", "https://fonts.gstatic.com"},
		ConnectSrc: []string{"'self'", "https://www.google-analytics.com"},
	}
	interceptor.WithContentSecurityPolicyProtection(p)
*/
func (interceptor *Interceptor) WithContentSecurityPolicyProtection(p policy.ContentSecurityPolicy) *Interceptor {
	interceptorFunc := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Add the CSP header to the response with the defined policy.
			w.Header().Add("Content-Security-Policy", policy.BuildContentSecurityPolicy(p))

			// Continue with the next middleware in the chain
			next.ServeHTTP(w, r)
		})
	}

	// Apply the middleware function
	interceptor.Use(interceptorFunc)

	// Return the modified MiddlewareChain
	return interceptor
}

/*
WithHSTS is a middleware function that adds a Strict-Transport-Security (HSTS)
header to the response based on the provided HSTSPolicy. HSTS is a web security policy
mechanism which helps to protect websites against protocol downgrade attacks and cookie hijacking.
It allows web servers to declare that web browsers (or other complying user agents) should interact
with it using only secure HTTPS connections, and never via the insecure HTTP protocol.

	Example:
	interceptor := intercept.NewInterceptor()
	p := policy.HSTSPolicy{
		MaxAge:           31536000,
		IncludeSubDomains: true,
		Preload:           true,
	}
	interceptor.WithHSTS(p)
*/
func (interceptor *Interceptor) WithHSTS(p policy.HSTSPolicy) *Interceptor {
	// Define the middleware function.
	interceptorFunc := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Construct the HSTS policy string from the provided policy.
			// max-age defines the duration (in seconds) that the browser should remember
			// that a site is only to be accessed using HTTPS.
			headerValue := fmt.Sprintf("max-age=%d", p.MaxAge)
			// If IncludeSubDomains is set to true, this rule applies to all of the site's subdomains as well.
			if p.IncludeSubDomains {
				headerValue += "; includeSubDomains"
			}
			// Preload allows the site to be included in the browser's preload list, meaning it should always be
			// accessed via HTTPS, even before the HSTS policy is received.
			if p.Preload {
				headerValue += "; preload"
			}

			// Add the Strict-Transport-Security header with the constructed policy to the response.
			w.Header().Add("Strict-Transport-Security", headerValue)

			// Call the next middleware function in the chain, or if there are no more, the final handler.
			next.ServeHTTP(w, r)
		})
	}

	// Add the middleware function to the chain.
	interceptor.Use(interceptorFunc)
	return interceptor
}

/*
WithLogging adds a logging middleware to the interceptor chain.

	Example:
	interceptor := intercept.NewInterceptor()
	p := policy.LoggingPolicy{
		LogDir: "/var/log/myapp",
	}
	interceptor.WithLogging(p)
*/
func (interceptor *Interceptor) WithLogging(p policy.LoggingPolicy) *Interceptor {
	interceptorFunc := func(next http.Handler) http.Handler {
		// Ensure the directory exists.
		if err := os.MkdirAll(p.LogDir, 0755); err != nil {
			log.Printf("Failed to create log directory %s: %v\n", p.LogDir, err)
			return next
		}

		logFile, err := os.OpenFile(filepath.Join(p.LogDir, "access.log"), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			log.Printf("Failed to open log file: %v\n", err)
			return next
		}

		accessLogger := log.New(logFile, "ACCESS: ", log.Ldate|log.Ltime|log.Lshortfile)

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Record the time the request started.
			start := time.Now()

			// Pass the request along to the next middleware.
			next.ServeHTTP(w, r)

			// When the next middleware has finished, record the time the request ended.
			end := time.Now()

			// Log the request details.
			accessLogger.Printf("%s %s %s %s\n", r.Method, r.RequestURI, r.RemoteAddr, end.Sub(start))
		})
	}

	// Add the middleware function to the chain.
	interceptor.Use(interceptorFunc)
	return interceptor
}

/*
Final chains the middleware and returns the final http.Handler.
The final handler is typically your application's main handler.

For Http handlers, this is where the http.HandlerFunc will be passed.

	myHandler := func(w http.ResponseWriter, r *http.Request) {
		// ...
	}

For GraphQL handlers, this is where the graphql.Handler will be passed.

	myGraphQLHandler := graphql.Handler{
		// ...
	}

	interceptor := intercept.NewInterceptor()
	... add middleware required for your application

	interceptor.Final(myHandler)

	-- OR --

	interceptor.Final(myGraphQLHandler)
*/
func (interceptor *Interceptor) Final(finalHandler http.Handler) http.Handler {
	for i := len(interceptor.Middleware) - 1; i >= 0; i-- {
		finalHandler = interceptor.Middleware[i](finalHandler)
	}

	return finalHandler
}
