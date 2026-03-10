package parser

// K8sObject is a generic representation of any parsed Kubernetes manifest.
type K8sObject struct {
	APIVersion  string
	Kind        string
	Name        string
	Namespace   string
	Labels      map[string]string
	Annotations map[string]string
	Spec        map[string]interface{}
	Raw         map[string]interface{}
	SourceFile  string
}

// ParseResult wraps parse outputs and any non-fatal errors.
type ParseResult struct {
	Objects []K8sObject
	Errors  []ParseError
}

// ParseError represents a non-fatal parse error.
type ParseError struct {
	File    string
	Message string
}
