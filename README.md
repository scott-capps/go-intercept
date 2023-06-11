# Go HTTP Middleware: Interceptor

Interceptor is a powerful HTTP middleware package for Go. It allows you to chain multiple middleware functions together to create a pipeline for your HTTP requests and responses.

## Table of Contents

1. [Getting Started](#getting-started)
2. [Middlewares](#middlewares)
   - [Use()](#use)
   - [WithCookie()](#withcookie)
   - [WithCookieParser()](#withcookieparser)
   - [WithLimitedHTTPVerbs()](#withlimitedhttpverbs)
   - [WithMaxBody()](#withmaxbody)
   - [WithCors()](#withcors)
   - [WithHeaderParser()](#withheaderparser)
   - [WithAllowedSchemes()](#withallowedschemes)
   - [WithContentSecurityPolicyProtection()](#withcontentsecuritypolicyprotection)
   - [WithHSTS()](#withhsts)
   - [WithLogger()](#withlogger)
3. [Final()](#final)

## [Getting Started](#getting-started)

You can install this package via `go get`:

`go get github.com/cappizzle/go-intercept`

To use it in your project, import it:

`import (
    "github.com/cappizzle/go-intercept/intercept"
)`

Here is a basic usage example:

```
interceptor := intercept.NewInterceptor()
interceptor.Use(middleware1).Use(middleware2) // and so on...
finalHandler := interceptor.Final(finalHTTPHandler)
```

## [Middlewares](#middlewares)

Interceptor comes with various inbuilt middlewares, each of which performs a different function. You can also easily create your own middleware and use it with Interceptor. All middleware functions in Interceptor return the modified Interceptor, which allows you to chain them together.

### `Use()`

[`Use()`](#use) allows you to add your own custom middleware to the interceptor. It returns the updated Interceptor to allow for method chaining.

### `WithCookie()`

[`WithCookie()`](#withcookie) sets a cookie in the HTTP response based on the provided cookie configuration.

```
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
```

### `WithCookieParser()`

[`WithCookieParser()`](#withcookieparser) parses cookies from the HTTP request.

```
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
```

### `WithLimitedHTTPVerbs()`

[`WithLimitedHTTPVerbs()`](#withlimitedhttpverbs) restricts the allowed HTTP methods based on the provided HTTP verb policy.

```
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
```

### `WithMaxBody()`

[`WithMaxBody()`](#withmaxbody) limits the size of the request body to a specified maximum size.

```
Example:
interceptor := middleware.NewMInterceptor()
maxSize := int64(1024 * 1024) // 1 MB
interceptor.WithMaxBody(maxSize)
```

### `WithCors()`

[`WithCors()`](#withcors) sets the Cross-Origin Resource Sharing (CORS) policy for the HTTP response.

```
Example:
interceptor := middleware.NewMInterceptor()
cp := policy.CorsPolicy{
  AllowOrigin:      "https://example.com",
  AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE"},
}
interceptor.WithCors(cp)
```

### `WithHeaderParser()`

[`WithHeaderParser()`](#withheaderparser) allows for parsing of specific headers and injecting them into the request's context.

```
Example:
interceptor := intercept.NewInterceptor()

policies := []policy.HeaderPolicy{
  {
    Header:         "Authorization",
    ErrorOnMissing: true,
    ContextKey: "auth-token",
  },
}

interceptor.WithHeaderParser(policies)
```

### `WithAllowedSchemes()`

[`WithAllowedSchemes()`](#withallowedschemes) restricts the allowed URL schemes based on the provided HTTP scheme policy.

```
Example:
interceptor := intercept.NewInterceptor()
p := policy.HttpSchemePolicy{
  Http:  true,
  Https: true,
}
interceptor.WithAllowedSchemes(p)
```

### `WithContentSecurityPolicyProtection()`

[`WithContentSecurityPolicyProtection()`](#withcontentsecuritypolicyprotection) sets the Content-Security-Policy header for the HTTP response.

```
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
```

### `WithHSTS()`

[`WithHSTS()`](#withhsts) sets the Strict-Transport-Security (HSTS) header for the HTTP response.

```
Example:
interceptor := intercept.NewInterceptor()
p := policy.HSTSPolicy{
  MaxAge:           31536000,
  IncludeSubDomains: true,
  Preload:           true,
}
interceptor.WithHSTS(p)
```

### `WithLogger()`

[`WithLogger()`](#withlogger) logs details about each request to a specified log directory.

```
Example:
interceptor := intercept.NewInterceptor()
p := policy.LoggingPolicy{
  LogDir: "/var/log/myapp",
}
interceptor.WithLogging(p)
```

### `Final()`

[Final()](#) wraps the provided final HTTP handler with the interceptor. This is the last function you call when setting up your interceptor.

```
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
```

For more information on how to use these middleware and examples, please refer to the provided links.
