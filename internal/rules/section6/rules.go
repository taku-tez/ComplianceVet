package section6

import "github.com/ComplianceVet/compliancevet/internal/rules"

func init() {
	for _, r := range All() {
		rules.Register(r)
	}
}

// All returns all Section 6 rules (PCI-DSS v4.0).
func All() []rules.Rule {
	return []rules.Rule{
		cv6001Rule{}, // Req 2: no default SA with permissions
		cv6002Rule{}, // Req 6: no 'latest' image tags
		cv6003Rule{}, // Req 7: no cluster-admin for workload SAs
		cv6004Rule{}, // Req 8: no anonymous auth
		cv6005Rule{}, // Req 10: audit log retention >= 365 days
		cv6006Rule{}, // Req 10: audit logging enabled
		cv6007Rule{}, // Req 11: CDE namespace isolation
		cv6008Rule{}, // Req 2: no privileged containers
	}
}
