package rules

import "github.com/ComplianceVet/compliancevet/internal/parser"

// Status represents the CIS compliance result for a single control.
type Status string

const (
	StatusPass          Status = "PASS"
	StatusFail          Status = "FAIL"
	StatusWarn          Status = "WARN"
	StatusNotApplicable Status = "NOT_APPLICABLE"
)

// Severity maps to remediation priority.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
)

// CISSection identifies which CIS benchmark section a rule belongs to.
type CISSection string

const (
	SectionControlPlane CISSection = "1"
	SectionEtcd         CISSection = "2"
	SectionWorkerNodes  CISSection = "3"
	SectionPolicies     CISSection = "4"
	SectionNSACISA      CISSection = "5"
	SectionPCIDSS       CISSection = "6"
)

// RuleContext carries all parsed manifests available to a rule at check time.
type RuleContext struct {
	Objects   []parser.K8sObject
	FilePaths []string
}

// CheckResult is the output of a single rule evaluation.
type CheckResult struct {
	RuleID      string
	CISRef      string
	Section     CISSection
	Status      Status
	Severity    Severity
	Description string
	Message     string
	Resource    string
	FilePath    string
	Remediation string
}

// Rule is the interface all CIS controls implement.
type Rule interface {
	ID() string
	CISRef() string
	Section() CISSection
	Severity() Severity
	Description() string
	Remediation() string
	Check(ctx RuleContext) []CheckResult
}

// SeverityOrder returns a numeric priority for severity (lower = more severe).
func SeverityOrder(s Severity) int {
	switch s {
	case SeverityCritical:
		return 0
	case SeverityHigh:
		return 1
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 3
	default:
		return 4
	}
}
