package section2

import "github.com/ComplianceVet/compliancevet/internal/rules"

func init() {
	for _, r := range All() {
		rules.Register(r)
	}
}

// All returns all Section 2 rules (etcd).
func All() []rules.Rule {
	return []rules.Rule{
		cv2001Rule{},
		cv2002Rule{},
		cv2003Rule{},
		cv2004Rule{},
		cv2005Rule{},
		cv2006Rule{},
	}
}
