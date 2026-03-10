package scorer

import (
	"github.com/ComplianceVet/compliancevet/internal/rules"
)

// SectionScore holds per-section compliance metrics.
type SectionScore struct {
	Section       rules.CISSection
	Name          string
	Score         float64
	TotalChecks   int
	Pass          int
	Fail          int
	Warn          int
	NotApplicable int
}

// OverallScore aggregates all sections.
type OverallScore struct {
	Score        float64
	Sections     []SectionScore
	CriticalFail int
	HighFail     int
	MediumFail   int
	LowFail      int
}

var sectionNames = map[rules.CISSection]string{
	rules.SectionControlPlane: "Control Plane",
	rules.SectionEtcd:         "etcd",
	rules.SectionWorkerNodes:  "Worker Nodes",
	rules.SectionPolicies:     "Policies",
	rules.SectionNSACISA:      "NSA/CISA",
	rules.SectionPCIDSS:       "PCI-DSS",
}

// sectionWeights for weighted overall score
var sectionWeights = map[rules.CISSection]float64{
	rules.SectionControlPlane: 0.20,
	rules.SectionEtcd:         0.10,
	rules.SectionWorkerNodes:  0.10,
	rules.SectionPolicies:     0.25,
	rules.SectionNSACISA:      0.20,
	rules.SectionPCIDSS:       0.15,
}

// Compute calculates the overall and per-section scores.
func Compute(results []rules.CheckResult) OverallScore {
	sections := []rules.CISSection{
		rules.SectionControlPlane,
		rules.SectionEtcd,
		rules.SectionWorkerNodes,
		rules.SectionPolicies,
		rules.SectionNSACISA,
		rules.SectionPCIDSS,
	}

	var sectionScores []SectionScore
	var weightedSum, totalWeight float64

	for _, sec := range sections {
		ss := computeSection(results, sec)
		sectionScores = append(sectionScores, ss)
		denom := ss.Pass + ss.Fail + ss.Warn
		if denom > 0 {
			w := sectionWeights[sec]
			weightedSum += ss.Score * w
			totalWeight += w
		}
	}

	overall := OverallScore{Sections: sectionScores}
	if totalWeight > 0 {
		overall.Score = weightedSum / totalWeight
	}

	for _, r := range results {
		if r.Status != rules.StatusFail {
			continue
		}
		switch r.Severity {
		case rules.SeverityCritical:
			overall.CriticalFail++
		case rules.SeverityHigh:
			overall.HighFail++
		case rules.SeverityMedium:
			overall.MediumFail++
		case rules.SeverityLow:
			overall.LowFail++
		}
	}

	return overall
}

func computeSection(results []rules.CheckResult, section rules.CISSection) SectionScore {
	ss := SectionScore{
		Section: section,
		Name:    sectionNames[section],
	}
	for _, r := range results {
		if r.Section != section {
			continue
		}
		switch r.Status {
		case rules.StatusPass:
			ss.Pass++
		case rules.StatusFail:
			ss.Fail++
		case rules.StatusWarn:
			ss.Warn++
		case rules.StatusNotApplicable:
			ss.NotApplicable++
		}
	}
	denom := ss.Pass + ss.Fail + ss.Warn
	ss.TotalChecks = denom + ss.NotApplicable
	if denom > 0 {
		ss.Score = (float64(ss.Pass) + float64(ss.Warn)*0.5) / float64(denom) * 100
	}
	return ss
}
