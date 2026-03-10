package report_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/ComplianceVet/compliancevet/internal/report"
	"github.com/ComplianceVet/compliancevet/internal/rules"
)

// TestWriteJSON_SeverityPreserved verifies that JSON output preserves all
// severity levels (CRITICAL/HIGH/MEDIUM/LOW/INFO) without collapsing them.
func TestWriteJSON_SeverityPreserved(t *testing.T) {
	severities := []rules.Severity{
		rules.SeverityCritical,
		rules.SeverityHigh,
		rules.SeverityMedium,
		rules.SeverityLow,
		rules.SeverityInfo,
	}

	results := make([]rules.CheckResult, len(severities))
	for i, sev := range severities {
		results[i] = rules.CheckResult{
			RuleID:      "CV4001",
			Section:     rules.SectionPolicies,
			Status:      rules.StatusFail,
			Severity:    sev,
			Description: "test rule",
			Message:     "test message",
		}
	}

	rep := report.New(results, nil)

	var buf bytes.Buffer
	if err := report.WriteJSON(&buf, rep); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	var decoded struct {
		Results []struct {
			Severity string `json:"Severity"`
		} `json:"Results"`
	}
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	if len(decoded.Results) != len(severities) {
		t.Fatalf("expected %d results, got %d", len(severities), len(decoded.Results))
	}

	for i, want := range severities {
		got := decoded.Results[i].Severity
		if got != string(want) {
			t.Errorf("result[%d]: want Severity=%q, got %q", i, want, got)
		}
	}
}

// TestWriteJSON_NotApplicableIncluded verifies that NOT_APPLICABLE results
// are included in the JSON output (not filtered), allowing consumers to
// handle them explicitly.
func TestWriteJSON_NotApplicableIncluded(t *testing.T) {
	results := []rules.CheckResult{
		{
			RuleID:   "CV1001",
			Section:  rules.SectionControlPlane,
			Status:   rules.StatusFail,
			Severity: rules.SeverityHigh,
			Message:  "anonymous auth enabled",
		},
		{
			RuleID:   "CV2001",
			Section:  rules.SectionEtcd,
			Status:   rules.StatusNotApplicable,
			Severity: rules.SeverityMedium,
			Message:  "etcd not found",
		},
	}

	rep := report.New(results, nil)

	var buf bytes.Buffer
	if err := report.WriteJSON(&buf, rep); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	var decoded struct {
		Results []struct {
			RuleID string `json:"RuleID"`
			Status string `json:"Status"`
		} `json:"Results"`
	}
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	if len(decoded.Results) != 2 {
		t.Fatalf("expected 2 results (including NOT_APPLICABLE), got %d", len(decoded.Results))
	}

	naFound := false
	for _, r := range decoded.Results {
		if r.RuleID == "CV2001" && r.Status == "NOT_APPLICABLE" {
			naFound = true
		}
	}
	if !naFound {
		t.Error("NOT_APPLICABLE result was not included in JSON output")
	}
}
