package checks

import (
	"fmt"
	"strings"
	"time"

	"github.com/cloudbusket/ai-auditor/audit-engine/internal/cloud"
)

// RunGCPChecks adds evidence-based GCP IAM findings to an existing report.
// Checks run only when their corresponding inventory category was collected
// completely. Missing or incomplete coverage never produces a PASS finding.
func RunGCPChecks(report *Report, inv cloud.Inventory) {
	if report == nil || inv.Provider != cloud.ProviderGCP {
		return
	}

	if coverageComplete(inv, "iam_policy", false) {
		checkGCPProjectIAM(report, inv)
		checkGCPPublicIAM(report, inv)
	}

	if coverageComplete(inv, "iam_service_account_keys", true) {
		checkGCPServiceAccountKeys(report, inv)
	}
}

func coverageComplete(inv cloud.Inventory, category string, allowNoData bool) bool {
	found := false

	for _, item := range inv.Coverage {
		if item.Provider != cloud.ProviderGCP || item.Category != category {
			continue
		}

		found = true
		if item.Status == cloud.CoverageCompleted {
			continue
		}
		if allowNoData && item.Status == cloud.CoverageNoData {
			continue
		}

		return false
	}

	return found
}

func checkGCPProjectIAM(report *Report, inv cloud.Inventory) {
	for _, resource := range inv.Resources {
		if resource.Type != "gcp.iam.binding" {
			continue
		}

		role, _ := resource.Properties["role"].(string)
		role = strings.TrimSpace(role)
		if role != "roles/owner" && role != "roles/editor" {
			continue
		}

		members, _ := resource.Properties["members"].([]string)
		if len(members) == 0 {
			continue
		}

		status := StatusWarning
		severity := "high"
		id := "GCP001"
		roleDescription := "Editor"
		if role == "roles/owner" {
			status = StatusCritical
			severity = "critical"
			roleDescription = "Owner"
		}

		evidence := map[string]any{
			"project_id":   inv.ProjectID,
			"role":         role,
			"members":      members,
			"member_count": len(members),
		}
		if condition, ok := resource.Properties["condition"]; ok {
			evidence["condition"] = condition
		}

		report.Add(Finding{
			ID:       id,
			Source:   "gcp",
			Category: "iam",
			Asset:    inv.ProjectID,
			Status:   status,
			Severity: severity,
			Message:  fmt.Sprintf("Project IAM grants the %s role to %d member(s)", roleDescription, len(members)),
			Description: "Broad project-level permissions increase the impact of compromised or misused identities. " +
				"This finding identifies the binding for review; it does not by itself prove that access is inappropriate.",
			Recommendation: "Review each listed member and confirm the access is required. Prefer narrower predefined or custom roles, " +
				"least-privilege resource scopes, and conditional bindings where appropriate.",
			Evidence: evidence,
		})
	}
}

func checkGCPPublicIAM(report *Report, inv cloud.Inventory) {
	publicPrincipals := map[string]bool{
		"allUsers":              true,
		"allAuthenticatedUsers": true,
	}

	for _, resource := range inv.Resources {
		if resource.Type != "gcp.iam.binding" {
			continue
		}

		role, _ := resource.Properties["role"].(string)
		role = strings.TrimSpace(role)

		members, _ := resource.Properties["members"].([]string)
		var exposed []string

		for _, member := range members {
			member = strings.TrimSpace(member)
			if publicPrincipals[member] {
				exposed = append(exposed, member)
			}
		}

		if len(exposed) == 0 {
			continue
		}

		status := StatusWarning
		severity := "high"

		if role == "roles/owner" || role == "roles/editor" {
			status = StatusCritical
			severity = "critical"
		}

		evidence := map[string]any{
			"project_id":          inv.ProjectID,
			"role":                role,
			"binding_members":     members,
			"public_principals":   exposed,
			"public_member_count": len(exposed),
		}

		if condition, ok := resource.Properties["condition"]; ok {
			evidence["condition"] = condition
		}

		report.Add(Finding{
			ID:       "GCP003",
			Source:   "gcp",
			Category: "iam",
			Asset:    inv.ProjectID,
			Status:   status,
			Severity: severity,
			Message: fmt.Sprintf(
				"Project IAM grants %s to %d public principal(s)",
				role,
				len(exposed),
			),
			Description: "The IAM binding includes allUsers or allAuthenticatedUsers. " +
				"This can expose the granted permissions beyond the intended identities. " +
				"Conditional bindings must be reviewed together with their expressions.",
			Recommendation: "Review whether public access is explicitly required. Remove public principals " +
				"where they are unnecessary, prefer specific identities, and verify any IAM condition " +
				"before changing the binding.",
			Evidence: evidence,
		})
	}
}

func checkGCPServiceAccountKeys(report *Report, inv cloud.Inventory) {
	now := time.Now().UTC()
	activeKeys := 0

	for _, resource := range inv.Resources {
		if resource.Type != "gcp.iam.service_account_key" {
			continue
		}

		props := resource.Properties
		disabled, _ := props["disabled"].(bool)
		if disabled {
			continue
		}

		validAfter, _ := props["valid_after_time"].(string)
		if validAfter != "" {
			start, err := time.Parse(time.RFC3339, validAfter)
			if err == nil && now.Before(start) {
				continue
			}
		}

		validBefore, _ := props["valid_before_time"].(string)
		if validBefore != "" {
			end, err := time.Parse(time.RFC3339, validBefore)
			if err == nil && !now.Before(end) {
				continue
			}
		}

		activeKeys++

		evidence := map[string]any{
			"key_name":              resource.Name,
			"service_account_email": props["service_account_email"],
			"key_type":              props["key_type"],
			"key_origin":            props["key_origin"],
			"valid_after_time":      validAfter,
			"valid_before_time":     validBefore,
			"disabled":              disabled,
		}

		if reason, ok := props["disable_reason"]; ok {
			evidence["disable_reason"] = reason
		}

		report.Add(Finding{
			ID:       "GCP002",
			Source:   "gcp",
			Category: "iam",
			Asset:    resource.Name,
			Status:   StatusWarning,
			Severity: "high",
			Message:  "Active user-managed service-account key found",
			Description: "User-managed service-account keys are long-lived credentials that can be copied and used outside Google Cloud. " +
				"The presence of a key does not prove it has been exposed or compromised.",
			Recommendation: "Prefer workload identity or service-account impersonation where possible. " +
				"If a user-managed key is required, restrict its use, protect its storage, rotate it regularly, and monitor its activity.",
			Evidence: evidence,
		})
	}

	if activeKeys == 0 {
		report.Add(Finding{
			ID:          "GCP002",
			Source:      "gcp",
			Category:    "iam",
			Asset:       inv.ProjectID,
			Status:      StatusPass,
			Severity:    "info",
			Message:     "No active user-managed service-account keys were found",
			Description: "The available service-account key inventory contained no keys that were currently enabled and within their validity period.",
			Evidence: map[string]any{
				"project_id":       inv.ProjectID,
				"active_key_count": 0,
			},
		})
	}
}
