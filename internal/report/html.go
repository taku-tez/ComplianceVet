package report

import (
	"fmt"
	"html/template"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/ComplianceVet/compliancevet/internal/rules"
	"github.com/ComplianceVet/compliancevet/internal/scorer"
)

// WriteHTML writes a self-contained HTML compliance report to w.
func WriteHTML(w io.Writer, rep Report) error {
	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"statusClass": func(s rules.Status) string {
			switch s {
			case rules.StatusPass:
				return "pass"
			case rules.StatusFail:
				return "fail"
			case rules.StatusWarn:
				return "warn"
			default:
				return "na"
			}
		},
		"severityClass": func(s rules.Severity) string {
			return strings.ToLower(string(s))
		},
		"scoreClass": func(score float64) string {
			switch {
			case score >= 80:
				return "score-good"
			case score >= 60:
				return "score-warn"
			default:
				return "score-bad"
			}
		},
		"formatScore": func(f float64) string {
			return fmt.Sprintf("%.0f", f)
		},
		"sectionName": func(sec rules.CISSection) string {
			names := map[rules.CISSection]string{
				rules.SectionControlPlane: "Control Plane",
				rules.SectionEtcd:         "etcd",
				rules.SectionWorkerNodes:  "Worker Nodes",
				rules.SectionPolicies:     "Policies",
				rules.SectionNSACISA:      "NSA/CISA",
				rules.SectionPCIDSS:       "PCI-DSS",
			}
			if n, ok := names[sec]; ok {
				return n
			}
			return string(sec)
		},
		"now": func() string {
			return time.Now().Format("2006-01-02 15:04:05 UTC")
		},
		"filterSection": func(results []rules.CheckResult, sec rules.CISSection) []rules.CheckResult {
			var out []rules.CheckResult
			for _, r := range results {
				if r.Section == sec {
					out = append(out, r)
				}
			}
			sort.Slice(out, func(i, j int) bool {
				si := rules.SeverityOrder(out[i].Severity)
				sj := rules.SeverityOrder(out[j].Severity)
				if si != sj {
					return si < sj
				}
				return out[i].RuleID < out[j].RuleID
			})
			return out
		},
		"failOnly": func(results []rules.CheckResult) []rules.CheckResult {
			var out []rules.CheckResult
			for _, r := range results {
				if r.Status == rules.StatusFail || r.Status == rules.StatusWarn {
					out = append(out, r)
				}
			}
			return out
		},
	}).Parse(htmlTemplate)
	if err != nil {
		return err
	}

	sections := []rules.CISSection{
		rules.SectionControlPlane,
		rules.SectionEtcd,
		rules.SectionWorkerNodes,
		rules.SectionPolicies,
		rules.SectionNSACISA,
		rules.SectionPCIDSS,
	}

	return tmpl.Execute(w, map[string]interface{}{
		"Report":   rep,
		"Score":    rep.Score,
		"Sections": sections,
		"Now":      time.Now().Format("2006-01-02 15:04:05 UTC"),
	})
}

func findSectionScore(sections []scorer.SectionScore, sec rules.CISSection) *scorer.SectionScore {
	for i := range sections {
		if sections[i].Section == sec {
			return &sections[i]
		}
	}
	return nil
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ComplianceVet Report</title>
<style>
  :root {
    --pass: #22c55e; --fail: #ef4444; --warn: #f59e0b; --na: #94a3b8;
    --critical: #7c3aed; --high: #ef4444; --medium: #f59e0b; --low: #3b82f6;
    --bg: #0f172a; --surface: #1e293b; --border: #334155;
    --text: #e2e8f0; --muted: #94a3b8;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg); color: var(--text); padding: 2rem; }
  h1 { font-size: 1.75rem; font-weight: 700; margin-bottom: 0.25rem; }
  h2 { font-size: 1.1rem; font-weight: 600; color: var(--muted); margin-bottom: 0.5rem; }
  h3 { font-size: 1rem; font-weight: 600; margin: 1.5rem 0 0.5rem; }
  .subtitle { color: var(--muted); font-size: 0.875rem; margin-bottom: 2rem; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin: 1.5rem 0; }
  .card { background: var(--surface); border: 1px solid var(--border); border-radius: 0.75rem; padding: 1.25rem; }
  .card-title { font-size: 0.75rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.5rem; }
  .card-value { font-size: 2rem; font-weight: 700; }
  .score-good { color: var(--pass); }
  .score-warn { color: var(--warn); }
  .score-bad  { color: var(--fail); }
  .section-card { background: var(--surface); border: 1px solid var(--border); border-radius: 0.75rem; padding: 1.25rem; margin-bottom: 1rem; }
  .section-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; }
  .section-name { font-weight: 600; font-size: 1rem; }
  .progress-bar { background: var(--border); border-radius: 999px; height: 6px; margin: 0.5rem 0; }
  .progress-fill { height: 100%; border-radius: 999px; background: var(--pass); }
  .progress-fill.score-warn { background: var(--warn); }
  .progress-fill.score-bad { background: var(--fail); }
  .stats { display: flex; gap: 1rem; font-size: 0.75rem; color: var(--muted); }
  .stat-pass { color: var(--pass); } .stat-fail { color: var(--fail); } .stat-warn { color: var(--warn); }
  table { width: 100%; border-collapse: collapse; font-size: 0.8rem; }
  th { text-align: left; padding: 0.5rem 0.75rem; color: var(--muted); font-weight: 500; border-bottom: 1px solid var(--border); }
  td { padding: 0.5rem 0.75rem; border-bottom: 1px solid var(--border); vertical-align: top; }
  tr:last-child td { border-bottom: none; }
  .badge { display: inline-block; padding: 0.125rem 0.5rem; border-radius: 999px; font-size: 0.7rem; font-weight: 600; }
  .badge.pass { background: #14532d; color: var(--pass); }
  .badge.fail { background: #450a0a; color: var(--fail); }
  .badge.warn { background: #451a03; color: var(--warn); }
  .badge.na   { background: #1e293b; color: var(--muted); }
  .badge.critical { background: #2e1065; color: #a78bfa; }
  .badge.high { background: #450a0a; color: var(--fail); }
  .badge.medium { background: #451a03; color: var(--warn); }
  .badge.low  { background: #172554; color: #93c5fd; }
  .remediation { font-size: 0.7rem; color: var(--muted); margin-top: 0.25rem; }
  .summary-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 0.75rem; margin: 1rem 0; }
  .summary-item { text-align: center; padding: 0.75rem; background: var(--surface); border-radius: 0.5rem; border: 1px solid var(--border); }
  .summary-num { font-size: 1.5rem; font-weight: 700; }
  .summary-label { font-size: 0.7rem; color: var(--muted); margin-top: 0.25rem; }
  @media print { body { background: white; color: black; } .card, .section-card { border: 1px solid #ccc; } }
</style>
</head>
<body>

<h1>ComplianceVet Compliance Report</h1>
<div class="subtitle">Generated: {{.Now}} | Standards: CIS Kubernetes Benchmark v1.9 · NSA/CISA Hardening Guide · PCI-DSS v4.0</div>

<!-- Overall Score -->
<div class="grid">
  <div class="card">
    <div class="card-title">Overall Score</div>
    <div class="card-value {{scoreClass .Score.Score}}">{{formatScore .Score.Score}}<span style="font-size:1rem;color:var(--muted)">/100</span></div>
  </div>
  <div class="card">
    <div class="card-title">Critical Failures</div>
    <div class="card-value" style="color:var(--critical)">{{.Score.CriticalFail}}</div>
  </div>
  <div class="card">
    <div class="card-title">High Failures</div>
    <div class="card-value" style="color:var(--fail)">{{.Score.HighFail}}</div>
  </div>
  <div class="card">
    <div class="card-title">Files Scanned</div>
    <div class="card-value" style="color:var(--text)">{{len .Report.Files}}</div>
  </div>
</div>

<!-- Section Scores -->
<h3>Section Breakdown</h3>
<div style="margin-bottom:2rem">
{{range .Score.Sections}}
{{if gt .TotalChecks 0}}
<div class="section-card">
  <div class="section-header">
    <span class="section-name">Section {{.Section}}: {{.Name}}</span>
    <span class="card-value {{scoreClass .Score}}" style="font-size:1.25rem">{{formatScore .Score}}/100</span>
  </div>
  <div class="progress-bar">
    <div class="progress-fill {{scoreClass .Score}}" style="width:{{formatScore .Score}}%"></div>
  </div>
  <div class="stats">
    <span class="stat-pass">✓ PASS: {{.Pass}}</span>
    <span class="stat-fail">✗ FAIL: {{.Fail}}</span>
    <span class="stat-warn">⚠ WARN: {{.Warn}}</span>
    <span>— N/A: {{.NotApplicable}}</span>
  </div>
</div>
{{end}}
{{end}}
</div>

<!-- Findings by Section -->
<h3>Findings (FAIL &amp; WARN only)</h3>
{{range .Sections}}
{{$sectionResults := filterSection $.Report.Results .}}
{{$failResults := failOnly $sectionResults}}
{{if $failResults}}
<div class="section-card">
  <div class="section-header">
    <span class="section-name">Section {{.}}: {{sectionName .}}</span>
  </div>
  <table>
    <thead>
      <tr>
        <th>Rule ID</th><th>CIS Ref</th><th>Status</th><th>Severity</th><th>Resource</th><th>Message</th>
      </tr>
    </thead>
    <tbody>
    {{range $failResults}}
    <tr>
      <td><strong>{{.RuleID}}</strong></td>
      <td style="color:var(--muted);font-size:0.7rem">{{.CISRef}}</td>
      <td><span class="badge {{statusClass .Status}}">{{.Status}}</span></td>
      <td><span class="badge {{severityClass .Severity}}">{{.Severity}}</span></td>
      <td style="font-size:0.75rem;color:var(--muted)">{{.Resource}}</td>
      <td>
        {{.Message}}
        {{if .Remediation}}<div class="remediation">↳ {{.Remediation}}</div>{{end}}
      </td>
    </tr>
    {{end}}
    </tbody>
  </table>
</div>
{{end}}
{{end}}

<div style="margin-top:3rem;padding-top:1rem;border-top:1px solid var(--border);font-size:0.75rem;color:var(--muted)">
  Generated by ComplianceVet v0.5.0 · <a href="https://github.com/ComplianceVet/compliancevet" style="color:var(--muted)">github.com/ComplianceVet/compliancevet</a>
</div>

</body>
</html>`
