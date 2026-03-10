package checker

import (
	"github.com/ComplianceVet/compliancevet/internal/parser"
	"github.com/ComplianceVet/compliancevet/internal/rules"
)

// Config configures which rules to run.
type Config struct {
	IgnoreRules []string           // rule IDs to skip
	Sections    []rules.CISSection // empty = all sections
	MinSeverity rules.Severity     // minimum severity to include (empty = all)
}

// Run executes all registered rules against the given objects and returns results.
func Run(objects []parser.K8sObject, cfg Config) []rules.CheckResult {
	ignoreSet := make(map[string]bool, len(cfg.IgnoreRules))
	for _, id := range cfg.IgnoreRules {
		ignoreSet[id] = true
	}

	sectionSet := make(map[rules.CISSection]bool, len(cfg.Sections))
	for _, s := range cfg.Sections {
		sectionSet[s] = true
	}

	ctx := rules.RuleContext{Objects: objects}

	var results []rules.CheckResult
	for _, rule := range rules.AllRules() {
		if ignoreSet[rule.ID()] {
			continue
		}
		if len(sectionSet) > 0 && !sectionSet[rule.Section()] {
			continue
		}
		if cfg.MinSeverity != "" && !severityMeetsMinimum(rule.Severity(), cfg.MinSeverity) {
			continue
		}
		results = append(results, rule.Check(ctx)...)
	}
	return results
}

func severityMeetsMinimum(s, min rules.Severity) bool {
	return rules.SeverityOrder(s) <= rules.SeverityOrder(min)
}
