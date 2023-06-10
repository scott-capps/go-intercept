package policy

type HeaderPolicy struct {
	Header         string // the name of the header.
	ContextKey     string // the name of the context key for this header.
	ErrorOnMissing bool   // whether to return an error if the header is missing.
}
