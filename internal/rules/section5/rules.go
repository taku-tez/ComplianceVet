package section5

import "github.com/ComplianceVet/compliancevet/internal/rules"

func init() {
	for _, r := range All() {
		rules.Register(r)
	}
}

// All returns all Section 5 rules (NSA/CISA Kubernetes Hardening Guide).
func All() []rules.Rule {
	return []rules.Rule{
		// Pod Security
		cv5001Rule{}, // readOnlyRootFilesystem
		cv5002Rule{}, // drop ALL capabilities
		cv5003Rule{}, // seccomp profile
		cv5004Rule{}, // AppArmor profile
		// Network Isolation
		cv5005Rule{}, // default-deny ingress NetworkPolicy
		cv5006Rule{}, // default-deny egress NetworkPolicy
		cv5007Rule{}, // Ingress TLS
		cv5008Rule{}, // LoadBalancer source IP restriction
		// Authentication & Authorization
		cv5009Rule{}, // no cluster-admin for non-system accounts
		cv5010Rule{}, // ServiceAccount token automount disabled
		cv5011Rule{}, // no wildcard roles bound to users
		// Audit & Logging
		cv5012Rule{}, // audit log enabled
		cv5013Rule{}, // audit policy configured
	}
}
