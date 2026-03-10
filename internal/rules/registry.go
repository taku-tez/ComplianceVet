package rules

var registry []Rule

// Register adds a rule to the global registry.
func Register(r Rule) {
	registry = append(registry, r)
}

// AllRules returns all registered rules.
func AllRules() []Rule {
	return registry
}
