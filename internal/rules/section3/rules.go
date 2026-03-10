package section3

import "github.com/ComplianceVet/compliancevet/internal/rules"

func init() {
	for _, r := range All() {
		rules.Register(r)
	}
}

// All returns all Section 3 rules (Worker Nodes).
func All() []rules.Rule {
	return []rules.Rule{
		cv3001Rule{},
		cv3002Rule{},
		cv3003Rule{},
		cv3004Rule{},
		cv3005Rule{},
		cv3006Rule{},
	}
}
