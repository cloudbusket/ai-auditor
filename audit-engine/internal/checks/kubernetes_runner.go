package checks

import (
	"github.com/cloudbusket/ai-auditor/audit-engine/internal/inventory"
)

// RunKubernetesChecks collects infrastructure inventory and runs
// only the Kubernetes security checks.
func RunKubernetesChecks() Report {
	report := NewReport()

	inv, err := inventory.Collect()
	if err != nil {
		report.Add(Finding{
			ID:             "K8S000",
			Category:       "kubernetes",
			Asset:          "cluster",
			Status:         StatusError,
			Severity:       "high",
			Message:        "Unable to collect inventory required for Kubernetes checks: " + err.Error(),
			Description:    "The inventory collector failed before Kubernetes checks could run.",
			Recommendation: "Check auditor permissions and inspect the inventory collector errors.",
		})
		return report
	}

	checkKubernetes(&report, inv)

	return report
}
