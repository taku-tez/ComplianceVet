package report

import (
	"fmt"
	"io"
	"sort"

	"github.com/olekukonko/tablewriter"

	"github.com/ComplianceVet/compliancevet/internal/rules"
)

// WriteTable writes the report as a formatted table to w.
func WriteTable(w io.Writer, rep Report, verbose bool) {
	fmt.Fprintln(w, "\nComplianceVet — CIS Kubernetes Benchmark v1.9")
	if len(rep.Files) > 0 {
		fmt.Fprintf(w, "Scanned: %d file(s)\n\n", len(rep.Files))
	}

	table := tablewriter.NewWriter(w)
	table.Header([]string{"Rule ID", "CIS Ref", "Status", "Severity", "Resource", "Message"})

	results := make([]rules.CheckResult, len(rep.Results))
	copy(results, rep.Results)
	sort.Slice(results, func(i, j int) bool {
		si := rules.SeverityOrder(results[i].Severity)
		sj := rules.SeverityOrder(results[j].Severity)
		if si != sj {
			return si < sj
		}
		return results[i].RuleID < results[j].RuleID
	})

	for _, r := range results {
		if !verbose && (r.Status == rules.StatusPass || r.Status == rules.StatusNotApplicable) {
			continue
		}
		msg := r.Message
		if msg == "" {
			msg = r.Description
		}
		if len(msg) > 60 {
			msg = msg[:57] + "..."
		}
		resource := r.Resource
		if len(resource) > 40 {
			resource = resource[:37] + "..."
		}
		table.Append([]string{
			r.RuleID,
			r.CISRef,
			string(r.Status),
			string(r.Severity),
			resource,
			msg,
		})
	}

	table.Render()

	fmt.Fprintf(w, "\nOverall Score: %.0f/100\n", rep.Score.Score)
	for _, ss := range rep.Score.Sections {
		fmt.Fprintf(w, "  Section %s (%s): %.0f/100  [PASS:%d FAIL:%d WARN:%d N/A:%d]\n",
			string(ss.Section), ss.Name, ss.Score, ss.Pass, ss.Fail, ss.Warn, ss.NotApplicable)
	}
}
