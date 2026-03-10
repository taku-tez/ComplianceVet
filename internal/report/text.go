package report

import (
	"fmt"
	"io"
	"sort"

	"github.com/ComplianceVet/compliancevet/internal/rules"
	"github.com/ComplianceVet/compliancevet/internal/scorer"
	"github.com/fatih/color"
)

var (
	colorPass   = color.New(color.FgGreen, color.Bold)
	colorFail   = color.New(color.FgRed, color.Bold)
	colorWarn   = color.New(color.FgYellow, color.Bold)
	colorNA     = color.New(color.FgHiBlack)
	colorHeader = color.New(color.FgCyan, color.Bold)
	colorScore  = color.New(color.FgWhite, color.Bold)
)

// WriteText writes a human-readable compliance report to w.
func WriteText(w io.Writer, rep Report, verbose bool) {
	fmt.Fprintln(w)
	colorHeader.Fprintln(w, "ComplianceVet — CIS Kubernetes Benchmark v1.9")
	fmt.Fprintln(w)

	if len(rep.Files) > 0 {
		fmt.Fprintf(w, "Scanned: %d file(s)\n\n", len(rep.Files))
	}

	sections := []rules.CISSection{
		rules.SectionControlPlane,
		rules.SectionEtcd,
		rules.SectionWorkerNodes,
		rules.SectionPolicies,
		rules.SectionNSACISA,
		rules.SectionPCIDSS,
	}

	for _, sec := range sections {
		ss := findSection(rep.Score.Sections, sec)
		if ss == nil {
			continue
		}
		if !verbose && ss.TotalChecks == ss.NotApplicable {
			continue
		}

		colorHeader.Fprintf(w, "\nSection %s: %s", string(sec), ss.Name)
		fmt.Fprintf(w, "  Score: %.0f/100\n", ss.Score)

		// Gather results for this section
		var sectionResults []rules.CheckResult
		for _, r := range rep.Results {
			if r.Section == sec {
				sectionResults = append(sectionResults, r)
			}
		}

		// Sort by severity then rule ID
		sort.Slice(sectionResults, func(i, j int) bool {
			si := rules.SeverityOrder(sectionResults[i].Severity)
			sj := rules.SeverityOrder(sectionResults[j].Severity)
			if si != sj {
				return si < sj
			}
			return sectionResults[i].RuleID < sectionResults[j].RuleID
		})

		for _, r := range sectionResults {
			if !verbose && r.Status == rules.StatusNotApplicable {
				continue
			}
			if !verbose && r.Status == rules.StatusPass {
				continue
			}
			printResult(w, r)
		}

		if verbose {
			for _, r := range sectionResults {
				if r.Status == rules.StatusPass || r.Status == rules.StatusNotApplicable {
					printResult(w, r)
				}
			}
		}
	}

	fmt.Fprintln(w)
	printOverallScore(w, rep.Score)
}

func printResult(w io.Writer, r rules.CheckResult) {
	statusStr := statusColored(r.Status)
	severityStr := fmt.Sprintf("%-8s", r.Severity)

	msg := r.Message
	if msg == "" {
		msg = r.Description
	}

	resource := r.Resource
	if resource != "" {
		resource = " [" + resource + "]"
	}

	fmt.Fprintf(w, "  %-8s %s  %-8s  %s%s\n",
		r.RuleID, statusStr, severityStr, msg, resource)

	if r.Status == rules.StatusFail && r.Remediation != "" {
		fmt.Fprintf(w, "           ↳ Remediation: %s\n", r.Remediation)
	}
}

func statusColored(s rules.Status) string {
	switch s {
	case rules.StatusPass:
		return colorPass.Sprintf("%-4s", "PASS")
	case rules.StatusFail:
		return colorFail.Sprintf("%-4s", "FAIL")
	case rules.StatusWarn:
		return colorWarn.Sprintf("%-4s", "WARN")
	default:
		return colorNA.Sprintf("%-4s", "N/A ")
	}
}

func printOverallScore(w io.Writer, score scorer.OverallScore) {
	colorScore.Fprintf(w, "Overall Score: %.0f/100\n", score.Score)

	var pass, fail, warn, na int
	for _, ss := range score.Sections {
		pass += ss.Pass
		fail += ss.Fail
		warn += ss.Warn
		na += ss.NotApplicable
	}
	fmt.Fprintf(w, "  PASS: %d  FAIL: %d  WARN: %d  NOT_APPLICABLE: %d\n\n",
		pass, fail, warn, na)

	if score.CriticalFail > 0 {
		colorFail.Fprintf(w, "  Critical failures: %d\n", score.CriticalFail)
	}
	if score.HighFail > 0 {
		colorFail.Fprintf(w, "  High failures:     %d\n", score.HighFail)
	}
	if score.MediumFail > 0 {
		colorWarn.Fprintf(w, "  Medium failures:   %d\n", score.MediumFail)
	}
	if score.LowFail > 0 {
		fmt.Fprintf(w, "  Low failures:      %d\n", score.LowFail)
	}
	fmt.Fprintln(w)
}

func findSection(sections []scorer.SectionScore, sec rules.CISSection) *scorer.SectionScore {
	for i := range sections {
		if sections[i].Section == sec {
			return &sections[i]
		}
	}
	return nil
}
