package checks

// applyRisk derives risk metadata from normalized severity.
// Risk is intentionally separate from finding status and policy severity.
func applyRisk(f *Finding) {
	if f == nil {
		return
	}

	var score int
	switch f.Severity {
	case "info":
		score = 0
	case "low":
		score = 20
	case "medium":
		score = 40
	case "high":
		score = 70
	case "critical":
		score = 90
	default:
		f.RiskScore = nil
		f.RiskBand = "unclassified"
		f.RiskPriority = "manual_review"
		return
	}

	f.RiskScore = &score

	switch {
	case score == 0:
		f.RiskBand = "informational"
		f.RiskPriority = "routine"
	case score <= 20:
		f.RiskBand = "low"
		f.RiskPriority = "routine"
	case score <= 40:
		f.RiskBand = "moderate"
		f.RiskPriority = "planned"
	case score <= 69:
		f.RiskBand = "high"
		f.RiskPriority = "urgent"
	case score <= 89:
		f.RiskBand = "very_high"
		f.RiskPriority = "urgent"
	default:
		f.RiskBand = "critical"
		f.RiskPriority = "immediate"
	}
}
