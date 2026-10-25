package checks

import (
	"encoding/json"
	"testing"
)

func TestNewReport(t *testing.T) {
	r := NewReport()

	if r.OverallStatus != StatusPass {
		t.Fatalf("expected pass, got %q", r.OverallStatus)
	}
	if r.Findings == nil || len(r.Findings) != 0 {
		t.Fatal("expected initialized empty findings")
	}
}

func TestReportSummaryAndSeverity(t *testing.T) {
	r := NewReport()
	r.Add(Finding{ID: "T1", Status: StatusPass})
	r.Add(Finding{ID: "T2", Status: StatusWarning})
	r.Add(Finding{ID: "T3", Status: StatusCritical})
	r.Add(Finding{ID: "T4", Status: StatusError})

	if r.Summary.Passed != 1 ||
		r.Summary.Warnings != 1 ||
		r.Summary.Critical != 1 ||
		r.Summary.Errors != 1 {
		t.Fatalf("unexpected summary: %+v", r.Summary)
	}

	if r.OverallStatus != StatusError {
		t.Fatalf("expected error, got %q", r.OverallStatus)
	}
}

func TestReportSeverityPrecedence(t *testing.T) {
	tests := []struct {
		name     string
		statuses []Status
		want     Status
	}{
		{"pass", []Status{StatusPass}, StatusPass},
		{"warning", []Status{StatusWarning}, StatusWarning},
		{"critical", []Status{StatusWarning, StatusCritical}, StatusCritical},
		{"error last", []Status{StatusCritical, StatusError}, StatusError},
		{"error remains highest", []Status{StatusError, StatusCritical}, StatusError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewReport()
			for _, s := range tt.statuses {
				r.Add(Finding{Status: s})
			}
			if r.OverallStatus != tt.want {
				t.Fatalf("expected %q, got %q", tt.want, r.OverallStatus)
			}
		})
	}
}

func TestReportJSON(t *testing.T) {
	r := NewReport()
	r.Add(Finding{
		ID: "DISK001", Category: "host", Status: StatusWarning,
		Severity: "medium", Message: "Disk usage is high",
		Recommendation: "Review disk usage",
	})

	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}

	for _, key := range []string{"generated_at", "overall_status", "summary", "findings"} {
		if _, ok := decoded[key]; !ok {
			t.Errorf("missing JSON field %q", key)
		}
	}
}
