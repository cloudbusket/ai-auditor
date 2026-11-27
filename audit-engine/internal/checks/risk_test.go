package checks

import "testing"

func TestApplyRiskSeverityMapping(t *testing.T) {
	tests := []struct {
		severity string
		score    int
		band     string
		priority string
	}{
		{"info", 0, "informational", "routine"},
		{"low", 20, "low", "routine"},
		{"medium", 40, "moderate", "planned"},
		{"high", 70, "very_high", "urgent"},
		{"critical", 90, "critical", "immediate"},
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			f := Finding{Severity: tt.severity}
			applyRisk(&f)

			if f.RiskScore == nil || *f.RiskScore != tt.score {
				t.Fatalf("score: got %v, want %d", f.RiskScore, tt.score)
			}
			if f.RiskBand != tt.band {
				t.Fatalf("band: got %q, want %q", f.RiskBand, tt.band)
			}
			if f.RiskPriority != tt.priority {
				t.Fatalf("priority: got %q, want %q", f.RiskPriority, tt.priority)
			}
		})
	}
}

func TestApplyRiskUnknownSeverityUnscored(t *testing.T) {
	f := Finding{Severity: "custom-risk"}
	applyRisk(&f)

	if f.RiskScore != nil {
		t.Fatal("unknown severity must remain unscored")
	}
	if f.RiskBand != "unclassified" || f.RiskPriority != "manual_review" {
		t.Fatalf("unexpected metadata: band=%q priority=%q",
			f.RiskBand, f.RiskPriority)
	}
}

func TestReportNormalizeDerivesRisk(t *testing.T) {
	report := Report{
		Findings: []Finding{
			{ID: "HIGH001", Severity: " HIGH "},
			{ID: "UNKNOWN001", Severity: "custom-risk"},
		},
	}
	report.Normalize()

	got := map[string]Finding{}
	for _, f := range report.Findings {
		got[f.ID] = f
	}

	high := got["HIGH001"]
	if high.RiskScore == nil || *high.RiskScore != 70 ||
		high.RiskBand != "very_high" || high.RiskPriority != "urgent" {
		t.Fatalf("unexpected high-risk result: %+v", high)
	}

	unknown := got["UNKNOWN001"]
	if unknown.RiskScore != nil ||
		unknown.RiskBand != "unclassified" ||
		unknown.RiskPriority != "manual_review" {
		t.Fatalf("unexpected unknown-risk result: %+v", unknown)
	}
}
