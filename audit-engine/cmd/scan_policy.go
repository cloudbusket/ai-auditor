package cmd

import (
	"fmt"
	"strings"

	"github.com/cloudbusket/ai-auditor/audit-engine/internal/checks"
)

type severityLevel int

const (
	severityInfo severityLevel = iota
	severityLow
	severityMedium
	severityHigh
	severityCritical
)

func parseSeverity(value string) (severityLevel, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "info":
		return severityInfo, true
	case "low":
		return severityLow, true
	case "medium":
		return severityMedium, true
	case "high":
		return severityHigh, true
	case "critical":
		return severityCritical, true
	default:
		return severityInfo, false
	}
}

func shouldFailOn(report checks.Report, threshold string) (bool, error) {
	threshold = strings.ToLower(strings.TrimSpace(threshold))

	if threshold == "" {
		threshold = "none"
	}

	if threshold == "none" {
		return false, nil
	}

	minimum, ok := parseSeverity(threshold)
	if !ok || minimum == severityInfo {
		return false, fmt.Errorf(
			"invalid fail-on threshold %q: use none, critical, high, medium, or low",
			threshold,
		)
	}

	breached := false

	for _, finding := range report.Findings {
		level, known := parseSeverity(finding.Severity)
		if !known {
			return false, fmt.Errorf(
				"finding %q has unsupported severity %q; cannot evaluate --fail-on %q",
				finding.ID,
				finding.Severity,
				threshold,
			)
		}

		if level >= minimum {
			breached = true
		}
	}

	return breached, nil
}
func validateFailOnThreshold(threshold string) error {
	_, err := shouldFailOn(checks.Report{}, threshold)
	return err
}
