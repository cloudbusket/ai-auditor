package checks

import (
	"testing"
	"time"

	"github.com/cloudbusket/ai-auditor/audit-engine/internal/cloud"
)

func gcpTestInventory() cloud.Inventory {
	return cloud.Inventory{
		Provider:  cloud.ProviderGCP,
		ProjectID: "test-project",
		Coverage: []cloud.Coverage{
			{
				Provider: cloud.ProviderGCP,
				Category: "iam_policy",
				Status:   cloud.CoverageCompleted,
			},
			{
				Provider: cloud.ProviderGCP,
				Category: "iam_service_account_keys",
				Status:   cloud.CoverageCompleted,
			},
		},
	}
}

func TestRunGCPChecksPrivilegedIAMBindings(t *testing.T) {
	inv := gcpTestInventory()
	for i := range inv.Coverage {
		if inv.Coverage[i].Category == "iam_service_account_keys" {
			inv.Coverage[i].Status = cloud.CoveragePermissionDenied
		}
	}
	inv.Resources = []cloud.Resource{
		{
			Type: "gcp.iam.binding",
			Properties: map[string]any{
				"role":    "roles/owner",
				"members": []string{"user:admin@example.com"},
			},
		},
		{
			Type: "gcp.iam.binding",
			Properties: map[string]any{
				"role":    "roles/editor",
				"members": []string{"serviceAccount:deploy@test-project.iam.gserviceaccount.com"},
			},
		},
		{
			Type: "gcp.iam.binding",
			Properties: map[string]any{
				"role":    "roles/viewer",
				"members": []string{"user:reader@example.com"},
			},
		},
	}

	report := NewReport()
	RunGCPChecks(&report, inv)

	if len(report.Findings) != 2 {
		t.Fatalf("expected two privileged IAM findings, got %d", len(report.Findings))
	}

	if report.Findings[0].ID != "GCP001" ||
		report.Findings[0].Status != StatusCritical {
		t.Errorf("expected critical Owner finding, got %+v", report.Findings[0])
	}

	if report.Findings[1].ID != "GCP001" ||
		report.Findings[1].Status != StatusWarning {
		t.Errorf("expected warning Editor finding, got %+v", report.Findings[1])
	}

	if report.Findings[0].Evidence["members"] == nil {
		t.Error("expected IAM member evidence")
	}
}

func TestRunGCPChecksPublicIAM(t *testing.T) {
	tests := []struct {
		name     string
		role     string
		member   string
		status   Status
		severity string
	}{
		{"allUsers viewer", "roles/viewer", "allUsers", StatusWarning, "high"},
		{"allAuthenticatedUsers viewer", "roles/viewer", "allAuthenticatedUsers", StatusWarning, "high"},
		{"public owner", "roles/owner", "allUsers", StatusCritical, "critical"},
		{"public editor", "roles/editor", "allAuthenticatedUsers", StatusCritical, "critical"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inv := gcpTestInventory()
			inv.Resources = []cloud.Resource{
				{
					Type: "gcp.iam.binding",
					Properties: map[string]any{
						"role":    tt.role,
						"members": []string{tt.member},
					},
				},
			}

			report := NewReport()
			RunGCPChecks(&report, inv)

			var finding *Finding
			for i := range report.Findings {
				if report.Findings[i].ID == "GCP003" {
					finding = &report.Findings[i]
					break
				}
			}

			if finding == nil {
				t.Fatalf("expected GCP003 finding; got %+v", report.Findings)
			}
			if finding.Status != tt.status {
				t.Errorf("expected status %s, got %s", tt.status, finding.Status)
			}
			if finding.Severity != tt.severity {
				t.Errorf("expected severity %s, got %s", tt.severity, finding.Severity)
			}
			if finding.Evidence["role"] != tt.role {
				t.Errorf("expected role %s, got %v", tt.role, finding.Evidence["role"])
			}

			principals, ok := finding.Evidence["public_principals"].([]string)
			if !ok || len(principals) != 1 || principals[0] != tt.member {
				t.Errorf("unexpected public principal evidence: %v", finding.Evidence["public_principals"])
			}
		})
	}
}

func TestRunGCPChecksPublicIAMPreservesCondition(t *testing.T) {
	inv := gcpTestInventory()
	condition := map[string]any{
		"title":      "Limited access",
		"expression": "request.time < timestamp('2027-01-01T00:00:00Z')",
	}
	inv.Resources = []cloud.Resource{
		{
			Type: "gcp.iam.binding",
			Properties: map[string]any{
				"role":      "roles/viewer",
				"members":   []string{"user:reader@example.com", "allUsers"},
				"condition": condition,
			},
		},
	}

	report := NewReport()
	RunGCPChecks(&report, inv)

	for _, finding := range report.Findings {
		if finding.ID == "GCP003" {
			if finding.Evidence["condition"] == nil {
				t.Error("expected IAM condition in evidence")
			}
			return
		}
	}

	t.Fatal("expected GCP003 finding")
}

func TestRunGCPChecksIgnoresNonPublicIAMMembers(t *testing.T) {
	inv := gcpTestInventory()
	inv.Resources = []cloud.Resource{
		{
			Type: "gcp.iam.binding",
			Properties: map[string]any{
				"role": "roles/viewer",
				"members": []string{
					"user:reader@example.com",
					"serviceAccount:app@test-project.iam.gserviceaccount.com",
					"group:admins@example.com",
				},
			},
		},
	}

	report := NewReport()
	RunGCPChecks(&report, inv)

	for _, finding := range report.Findings {
		if finding.ID == "GCP003" {
			t.Errorf("unexpected public IAM finding: %+v", finding)
		}
	}
}

func TestRunGCPChecksActiveServiceAccountKeys(t *testing.T) {
	inv := gcpTestInventory()
	inv.Resources = []cloud.Resource{
		{
			Name: "active-key",
			Type: "gcp.iam.service_account_key",
			Properties: map[string]any{
				"service_account_email": "app@test-project.iam.gserviceaccount.com",
				"key_type":              "USER_MANAGED",
				"key_origin":            "GOOGLE_PROVIDED",
				"disabled":              false,
			},
		},
		{
			Name: "disabled-key",
			Type: "gcp.iam.service_account_key",
			Properties: map[string]any{
				"disabled": true,
			},
		},
		{
			Name: "expired-key",
			Type: "gcp.iam.service_account_key",
			Properties: map[string]any{
				"disabled":          false,
				"valid_before_time": time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
			},
		},
		{
			Name: "future-key",
			Type: "gcp.iam.service_account_key",
			Properties: map[string]any{
				"disabled":         false,
				"valid_after_time": time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
			},
		},
	}

	report := NewReport()
	RunGCPChecks(&report, inv)

	if len(report.Findings) != 1 {
		t.Fatalf("expected one active-key finding, got %d", len(report.Findings))
	}

	finding := report.Findings[0]
	if finding.ID != "GCP002" || finding.Status != StatusWarning {
		t.Errorf("expected GCP002 warning, got %+v", finding)
	}

	if finding.Asset != "active-key" {
		t.Errorf("expected active-key asset, got %q", finding.Asset)
	}

	if finding.Evidence["service_account_email"] != "app@test-project.iam.gserviceaccount.com" {
		t.Errorf("service-account evidence missing: %+v", finding.Evidence)
	}
}

func TestRunGCPChecksNoActiveKeysPassesWithCompleteCoverage(t *testing.T) {
	inv := gcpTestInventory()
	inv.Resources = []cloud.Resource{
		{
			Name: "disabled-key",
			Type: "gcp.iam.service_account_key",
			Properties: map[string]any{
				"disabled": true,
			},
		},
	}

	report := NewReport()
	RunGCPChecks(&report, inv)

	if len(report.Findings) != 1 {
		t.Fatalf("expected one no-active-keys finding, got %d", len(report.Findings))
	}

	if report.Findings[0].Status != StatusPass {
		t.Errorf("expected pass, got %q", report.Findings[0].Status)
	}
}

func TestRunGCPChecksSkipsIncompleteOrMissingCoverage(t *testing.T) {
	tests := []struct {
		name     string
		coverage []cloud.Coverage
	}{
		{
			name: "missing IAM coverage",
		},
		{
			name: "permission denied",
			coverage: []cloud.Coverage{
				{Provider: cloud.ProviderGCP, Category: "iam_policy", Status: cloud.CoveragePermissionDenied},
				{Provider: cloud.ProviderGCP, Category: "iam_service_account_keys", Status: cloud.CoveragePermissionDenied},
			},
		},
		{
			name: "partial coverage",
			coverage: []cloud.Coverage{
				{Provider: cloud.ProviderGCP, Category: "iam_policy", Status: cloud.CoveragePartial},
				{Provider: cloud.ProviderGCP, Category: "iam_service_account_keys", Status: cloud.CoveragePartial},
			},
		},
		{
			name: "API disabled",
			coverage: []cloud.Coverage{
				{Provider: cloud.ProviderGCP, Category: "iam_policy", Status: cloud.CoverageAPIDisabled},
				{Provider: cloud.ProviderGCP, Category: "iam_service_account_keys", Status: cloud.CoverageAPIDisabled},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inv := gcpTestInventory()
			inv.Coverage = tt.coverage
			inv.Resources = []cloud.Resource{
				{
					Type: "gcp.iam.binding",
					Properties: map[string]any{
						"role":    "roles/owner",
						"members": []string{"user:admin@example.com"},
					},
				},
			}

			report := NewReport()
			RunGCPChecks(&report, inv)

			if len(report.Findings) != 0 {
				t.Errorf("expected no IAM findings when coverage is incomplete, got %+v",
					report.Findings)
			}
		})
	}
}

func TestRunGCPChecksIgnoresOtherProviders(t *testing.T) {
	inv := gcpTestInventory()
	inv.Provider = cloud.ProviderAWS

	report := NewReport()
	RunGCPChecks(&report, inv)

	if len(report.Findings) != 0 {
		t.Errorf("expected no GCP findings for AWS inventory, got %d", len(report.Findings))
	}
}

func TestRunGCPChecksNoServiceAccountsNoData(t *testing.T) {
	inv := gcpTestInventory()

	for i := range inv.Coverage {
		if inv.Coverage[i].Category == "iam_service_account_keys" {
			inv.Coverage[i].Status = cloud.CoverageNoData
		}
	}

	report := NewReport()
	RunGCPChecks(&report, inv)

	if len(report.Findings) != 1 {
		t.Fatalf("expected one no-active-keys finding, got %d", len(report.Findings))
	}

	finding := report.Findings[0]
	if finding.ID != "GCP002" || finding.Status != StatusPass {
		t.Errorf("expected GCP002 pass for no service accounts, got %+v", finding)
	}

	if finding.Evidence["active_key_count"] != 0 {
		t.Errorf("expected zero active keys, got %v",
			finding.Evidence["active_key_count"])
	}
}

func TestRunGCPChecksRejectsMixedCoverageRecords(t *testing.T) {
	inv := gcpTestInventory()
	inv.Coverage = append(inv.Coverage, cloud.Coverage{
		Provider: cloud.ProviderGCP,
		Category: "iam_service_account_keys",
		Status:   cloud.CoveragePartial,
	})

	report := NewReport()
	RunGCPChecks(&report, inv)

	if len(report.Findings) != 0 {
		t.Errorf("expected no findings with conflicting coverage, got %+v",
			report.Findings)
	}
}
