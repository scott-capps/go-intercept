package policy

type HSTSPolicy struct {
	MaxAge            int
	IncludeSubDomains bool
	Preload           bool
}
