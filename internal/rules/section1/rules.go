package section1

import "github.com/ComplianceVet/compliancevet/internal/rules"

func init() {
	for _, r := range All() {
		rules.Register(r)
	}
}

// All returns all Section 1 rules (Control Plane).
func All() []rules.Rule {
	return []rules.Rule{
		cv1001Rule{},
		cv1002Rule{},
		cv1003Rule{},
		cv1004Rule{},
		cv1005Rule{},
		cv1006Rule{},
		cv1007Rule{},
		cv1008Rule{},
		cv1009Rule{},
		cv1010Rule{},
		cv1011Rule{},
		cv1012Rule{},
		cv1013Rule{},
	}
}
