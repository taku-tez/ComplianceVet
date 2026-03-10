package report

import (
	"github.com/ComplianceVet/compliancevet/internal/rules"
	"github.com/ComplianceVet/compliancevet/internal/scorer"
)

// Report aggregates all scan results.
type Report struct {
	Results []rules.CheckResult
	Score   scorer.OverallScore
	Files   []string
}

// New creates a Report from check results.
func New(results []rules.CheckResult, files []string) Report {
	return Report{
		Results: results,
		Score:   scorer.Compute(results),
		Files:   files,
	}
}

// FailCount returns the number of FAIL results.
func (r Report) FailCount() int {
	n := 0
	for _, res := range r.Results {
		if res.Status == rules.StatusFail {
			n++
		}
	}
	return n
}
