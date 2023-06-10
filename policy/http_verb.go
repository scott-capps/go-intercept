package policy

type HttpVerbPolicy struct {
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
