package remediation

import (
	"strings"
)

const (
	maxSummaryBytes       = 2000
	maxRootCauseBytes     = 3000
	maxRiskBytes          = 2000
	maxProviderModelBytes = 128

	maxRemediationSteps = 10
	maxStepTitleBytes   = 200
	maxStepDescription  = 1500
	maxStepCommandBytes = 2000
	maxStepImpactBytes  = 500

	maxChecklistItems = 10
	maxChecklistBytes = 1000
)

func validateRemediationSolution(solution RemediationSolution) error {
	if strings.TrimSpace(solution.Summary) == "" ||
		strings.TrimSpace(solution.RootCause) == "" {
		return ErrInvalidResponse
	}

	if len(solution.Summary) > maxSummaryBytes ||
		len(solution.RootCause) > maxRootCauseBytes ||
		len(solution.Risk) > maxRiskBytes ||
		len(solution.Model) > maxProviderModelBytes {
		return ErrInvalidResponse
	}

	if solution.Confidence != "" {
		switch solution.Confidence {
		case "low", "medium", "high":
		default:
			return ErrInvalidResponse
		}
	}

	if len(solution.Steps) > maxRemediationSteps ||
		len(solution.Verification) > maxChecklistItems ||
		len(solution.Rollback) > maxChecklistItems ||
		len(solution.Assumptions) > maxChecklistItems {
		return ErrInvalidResponse
	}

	for _, step := range solution.Steps {
		if strings.TrimSpace(step.Title) == "" ||
			strings.TrimSpace(step.Description) == "" {
			return ErrInvalidResponse
		}

		if len(step.Title) > maxStepTitleBytes ||
			len(step.Description) > maxStepDescription ||
			len(step.Command) > maxStepCommandBytes ||
			len(step.Impact) > maxStepImpactBytes {
			return ErrInvalidResponse
		}
	}

	for _, items := range [][]string{
		solution.Verification,
		solution.Rollback,
		solution.Assumptions,
	} {
		for _, item := range items {
			if strings.TrimSpace(item) == "" ||
				len(item) > maxChecklistBytes {
				return ErrInvalidResponse
			}
		}
	}

	return nil
}

func sanitizeRemediationSolution(solution RemediationSolution) RemediationSolution {
	solution.Provider = sanitizeText(solution.Provider, 128)
	solution.Model = sanitizeText(solution.Model, maxProviderModelBytes)
	solution.Summary = sanitizeText(solution.Summary, maxSummaryBytes)
	solution.RootCause = sanitizeText(solution.RootCause, maxRootCauseBytes)
	solution.Risk = sanitizeText(solution.Risk, maxRiskBytes)

	for i := range solution.Steps {
		solution.Steps[i].Title = sanitizeText(
			solution.Steps[i].Title,
			maxStepTitleBytes,
		)
		solution.Steps[i].Description = sanitizeText(
			solution.Steps[i].Description,
			maxStepDescription,
		)
		solution.Steps[i].Command = sanitizeText(
			solution.Steps[i].Command,
			maxStepCommandBytes,
		)
		solution.Steps[i].Impact = sanitizeText(
			solution.Steps[i].Impact,
			maxStepImpactBytes,
		)
	}

	sanitizeList := func(items []string) {
		for i := range items {
			items[i] = sanitizeText(items[i], maxChecklistBytes)
		}
	}

	sanitizeList(solution.Verification)
	sanitizeList(solution.Rollback)
	sanitizeList(solution.Assumptions)

	return solution
}
