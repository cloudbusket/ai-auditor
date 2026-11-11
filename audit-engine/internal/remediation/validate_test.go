package remediation

import (
	"strings"
	"testing"
)

func validRemediationSolution() RemediationSolution {
	return RemediationSolution{
		Summary:    "Review disk usage",
		RootCause:  "The root filesystem is nearly full",
		Risk:       "Applications may fail to write data",
		Confidence: "high",
		Steps: []RemediationStep{
			{
				Title:       "Inspect disk usage",
				Description: "Identify which directories consume the most space",
				Command:     "df -h",
				Impact:      "Read-only inspection",
			},
		},
		Verification: []string{"Check filesystem usage again"},
		Rollback:     []string{"No changes were made"},
		Assumptions:  []string{"The reported filesystem is the root filesystem"},
	}
}

func TestValidateRemediationSolutionAcceptsValidResponse(t *testing.T) {
	if err := validateRemediationSolution(validRemediationSolution()); err != nil {
		t.Fatalf("expected valid response, got %v", err)
	}
}

func TestValidateRemediationSolutionRejectsInvalidConfidence(t *testing.T) {
	solution := validRemediationSolution()
	solution.Confidence = "certain"

	if err := validateRemediationSolution(solution); err == nil {
		t.Fatal("expected invalid confidence to be rejected")
	}
}

func TestValidateRemediationSolutionRejectsOversizedFields(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*RemediationSolution)
	}{
		{
			name: "summary",
			mutate: func(s *RemediationSolution) {
				s.Summary = strings.Repeat("A", maxSummaryBytes+1)
			},
		},
		{
			name: "root cause",
			mutate: func(s *RemediationSolution) {
				s.RootCause = strings.Repeat("A", maxRootCauseBytes+1)
			},
		},
		{
			name: "step command",
			mutate: func(s *RemediationSolution) {
				s.Steps[0].Command = strings.Repeat("A", maxStepCommandBytes+1)
			},
		},
		{
			name: "verification item",
			mutate: func(s *RemediationSolution) {
				s.Verification[0] = strings.Repeat("A", maxChecklistBytes+1)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			solution := validRemediationSolution()
			tt.mutate(&solution)

			if err := validateRemediationSolution(solution); err == nil {
				t.Fatal("expected oversized response to be rejected")
			}
		})
	}
}

func TestValidateRemediationSolutionRejectsExcessiveLists(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*RemediationSolution)
	}{
		{
			name: "steps",
			mutate: func(s *RemediationSolution) {
				s.Steps = make([]RemediationStep, maxRemediationSteps+1)
			},
		},
		{
			name: "verification",
			mutate: func(s *RemediationSolution) {
				s.Verification = make([]string, maxChecklistItems+1)
			},
		},
		{
			name: "rollback",
			mutate: func(s *RemediationSolution) {
				s.Rollback = make([]string, maxChecklistItems+1)
			},
		},
		{
			name: "assumptions",
			mutate: func(s *RemediationSolution) {
				s.Assumptions = make([]string, maxChecklistItems+1)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			solution := validRemediationSolution()
			tt.mutate(&solution)

			if err := validateRemediationSolution(solution); err == nil {
				t.Fatal("expected excessive list size to be rejected")
			}
		})
	}
}

func TestValidateRemediationSolutionRejectsIncompleteStep(t *testing.T) {
	solution := validRemediationSolution()
	solution.Steps[0].Description = ""

	if err := validateRemediationSolution(solution); err == nil {
		t.Fatal("expected incomplete remediation step to be rejected")
	}
}

func TestSanitizeRemediationSolutionRedactsSecrets(t *testing.T) {
	solution := validRemediationSolution()
	solution.Summary = "Review API_KEY=super-secret-value"
	solution.Steps[0].Command = "curl -H 'Authorization: Bearer abc123secret'"

	solution = sanitizeRemediationSolution(solution)

	if strings.Contains(solution.Summary, "super-secret-value") {
		t.Error("summary contains an unredacted secret")
	}

	if strings.Contains(solution.Steps[0].Command, "abc123secret") {
		t.Error("command contains an unredacted bearer token")
	}
}
