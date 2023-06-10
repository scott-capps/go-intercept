package policy

import "strings"

type ContentSecurityPolicy struct {
	// The default-src directive serves as a fallback for the other CSP fetch directives.
	// For each of the following directives that are absent, the user agent will look for the default-src directive and will use this value for it.
	DefaultSrc              []string
	ScriptSrc               []string
	StyleSrc                []string
	ImgSrc                  []string
	ConnectSrc              []string
	FontSrc                 []string
	ObjectSrc               []string
	MediaSrc                []string
	FrameSrc                []string
	ChildSrc                []string
	FormAction              []string
	FrameAncestors          []string
	PluginTypes             []string
	ReportUri               string
	ReportOnly              bool
	Sandbox                 []string
	WorkerSrc               []string
	ManifestSrc             []string
	NavigateTo              []string
	UpgradeInsecureRequests bool
	BlockAllMixedContent    bool
}

func buildCSPDirective(directive string, values []string) string {
	if len(values) == 0 {
		return ""
	}
	return directive + " " + strings.Join(values, " ")
}

func BuildContentSecurityPolicy(policy ContentSecurityPolicy) string {
	var response strings.Builder

	response.WriteString(buildCSPDirective("default-src", policy.DefaultSrc))
	response.WriteString(buildCSPDirective("script-src", policy.ScriptSrc))
	response.WriteString(buildCSPDirective("style-src", policy.StyleSrc))
	response.WriteString(buildCSPDirective("img-src", policy.ImgSrc))
	response.WriteString(buildCSPDirective("connect-src", policy.ConnectSrc))
	response.WriteString(buildCSPDirective("font-src", policy.FontSrc))
	response.WriteString(buildCSPDirective("object-src", policy.ObjectSrc))
	response.WriteString(buildCSPDirective("media-src", policy.MediaSrc))
	response.WriteString(buildCSPDirective("frame-src", policy.FrameSrc))
	response.WriteString(buildCSPDirective("child-src", policy.ChildSrc))
	response.WriteString(buildCSPDirective("form-action", policy.FormAction))
	response.WriteString(buildCSPDirective("frame-ancestors", policy.FrameAncestors))
	response.WriteString(buildCSPDirective("plugin-types", policy.PluginTypes))
	response.WriteString(buildCSPDirective("report-uri", []string{policy.ReportUri}))
	response.WriteString(buildCSPDirective("sandbox", policy.Sandbox))
	response.WriteString(buildCSPDirective("worker-src", policy.WorkerSrc))
	response.WriteString(buildCSPDirective("manifest-src", policy.ManifestSrc))
	response.WriteString(buildCSPDirective("navigate-to", policy.NavigateTo))

	if policy.ReportOnly {
		response.WriteString("; report-only")
	}

	if policy.UpgradeInsecureRequests {
		response.WriteString("; upgrade-insecure-requests")
	}

	if policy.BlockAllMixedContent {
		response.WriteString("; block-all-mixed-content")
	}

	// Trim the final string to remove potential leading/trailing white spaces and return
	return strings.TrimSpace(response.String())
}
