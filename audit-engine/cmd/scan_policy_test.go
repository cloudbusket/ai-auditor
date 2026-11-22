package cmd

import (
	"testing"

	"github.com/cloudbusket/ai-auditor/audit-engine/internal/checks"
)

func TestShouldFailOn(t *testing.T) {
	tests := []struct {
		name      string
		threshold string
		severity  string
		want      bool
		wantErr   bool
	}{
		{"none ignores critical", "none", "critical", false, false},
		{"critical matches critical", "critical", "critical", true, false},
		{"critical ignores high", "critical", "high", false, false},
		{"high matches critical", "high", "critical", true, false},
		{"high matches high", "high", "high", true, false},
		{"high ignores medium", "high", "medium", false, false},
		{"medium matches medium", "medium", "medium", true, false},
		{"low matches low", "low", "low", true, false},
		{"low ignores info", "low", "info", false, false},
		{"case insensitive", "HIGH", "CRITICAL", true, false},
		{"invalid threshold", "urgent", "critical", false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := checks.Report{
				Findings: []checks.Finding{
					{ID: "TEST001", Severity: tt.severity},
				},
			}

			got, err := shouldFailOn(report, tt.threshold)

			if (err != nil) != tt.wantErr {
				t.Fatalf("shouldFailOn() error = %v, wantErr %v", err, tt.wantErr)
			}

			if got != tt.want {
				t.Errorf("shouldFailOn() = %v, want %v", got, tt.want)
			}
		})
	}
}
