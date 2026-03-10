package section4

import "github.com/ComplianceVet/compliancevet/internal/rules"

func init() {
	for _, r := range All() {
		rules.Register(r)
	}
}

// All returns all Section 4 rules (Kubernetes Policies).
func All() []rules.Rule {
	return []rules.Rule{
		cv4001Rule{},
		cv4002Rule{},
		cv4003Rule{},
		cv4004Rule{},
		cv4005Rule{},
		cv4006Rule{},
		cv4007Rule{},
		cv4008Rule{},
		cv4009Rule{},
		cv4010Rule{},
		cv4011Rule{},
		cv4012Rule{},
	}
}
