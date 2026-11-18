package checks

import (
	"testing"

	"github.com/cloudbusket/ai-auditor/audit-engine/internal/cloud"
)

func awsTestInventory(status cloud.CoverageStatus) cloud.Inventory {
	return cloud.Inventory{
		Provider:  cloud.ProviderAWS,
		AccountID: "123456789012",
		Coverage: []cloud.Coverage{
			{
				Provider: cloud.ProviderAWS,
				Category: "ec2_instances",
				Status:   status,
			},
		},
	}
}

func TestRunAWSChecksPublicIP(t *testing.T) {
	inv := awsTestInventory(cloud.CoverageCompleted)
	inv.Resources = []cloud.Resource{
		{
			ID:       "i-0123456789abcdef0",
			Name:     "web-server",
			Type:     "aws.ec2.instance",
			Provider: cloud.ProviderAWS,
			Region:   "ap-southeast-2",
			Zone:     "ap-southeast-2a",
			Properties: map[string]any{
				"public_ip":         "203.0.113.10",
				"instance_type":     "t3.small",
				"state":             "running",
				"vpc_id":            "vpc-123",
				"subnet_id":         "subnet-123",
				"security_groups":   []string{"sg-123"},
				"availability_zone": "ap-southeast-2a",
			},
		},
	}

	report := NewReport()
	RunAWSChecks(&report, inv)

	if len(report.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(report.Findings))
	}

	f := report.Findings[0]

	if f.ID != "AWS001" {
		t.Errorf("expected AWS001, got %q", f.ID)
	}
	if f.Source != "aws" {
		t.Errorf("expected source aws, got %q", f.Source)
	}
	if f.Category != "network_exposure" {
		t.Errorf("expected network_exposure, got %q", f.Category)
	}
	if f.Asset != "i-0123456789abcdef0" {
		t.Errorf("unexpected asset: %q", f.Asset)
	}
	if f.Status != StatusWarning {
		t.Errorf("expected warning, got %q", f.Status)
	}
	if f.Severity != "medium" {
		t.Errorf("expected medium severity, got %q", f.Severity)
	}
	if f.Evidence["public_ip"] != "203.0.113.10" {
		t.Errorf("unexpected public IP evidence: %v", f.Evidence["public_ip"])
	}
	if f.Evidence["instance_type"] != "t3.small" {
		t.Errorf("unexpected instance type evidence: %v", f.Evidence["instance_type"])
	}
	if report.Summary.Warnings != 1 {
		t.Errorf("expected 1 warning in summary, got %d", report.Summary.Warnings)
	}
	if report.OverallStatus != StatusWarning {
		t.Errorf("expected overall warning, got %q", report.OverallStatus)
	}
}

func TestRunAWSChecksPrivateInstance(t *testing.T) {
	inv := awsTestInventory(cloud.CoverageCompleted)
	inv.Resources = []cloud.Resource{
		{
			ID:       "i-private",
			Name:     "private-server",
			Type:     "aws.ec2.instance",
			Provider: cloud.ProviderAWS,
			Properties: map[string]any{
				"public_ip":  "",
				"private_ip": "10.0.1.10",
			},
		},
	}

	report := NewReport()
	RunAWSChecks(&report, inv)

	if len(report.Findings) != 0 {
		t.Errorf("expected no findings for private instance, got %+v", report.Findings)
	}
}

func TestRunAWSChecksIgnoresIncompleteCoverage(t *testing.T) {
	tests := []struct {
		name   string
		status cloud.CoverageStatus
	}{
		{"partial", cloud.CoveragePartial},
		{"permission denied", cloud.CoveragePermissionDenied},
		{"API disabled", cloud.CoverageAPIDisabled},
		{"not configured", cloud.CoverageNotConfigured},
		{"error", cloud.CoverageError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inv := awsTestInventory(tt.status)
			inv.Resources = []cloud.Resource{
				{
					ID:   "i-public",
					Type: "aws.ec2.instance",
					Properties: map[string]any{
						"public_ip": "203.0.113.10",
					},
				},
			}

			report := NewReport()
			RunAWSChecks(&report, inv)

			if len(report.Findings) != 0 {
				t.Errorf("expected no findings with %s coverage, got %+v",
					tt.status, report.Findings)
			}
		})
	}
}

func TestRunAWSChecksNoDataCoverage(t *testing.T) {
	inv := awsTestInventory(cloud.CoverageNoData)

	report := NewReport()
	RunAWSChecks(&report, inv)

	if len(report.Findings) != 0 {
		t.Errorf("expected no findings for empty inventory, got %+v", report.Findings)
	}
}

func TestRunAWSChecksIgnoresGCPInventory(t *testing.T) {
	inv := awsTestInventory(cloud.CoverageCompleted)
	inv.Provider = cloud.ProviderGCP
	inv.Coverage[0].Provider = cloud.ProviderGCP
	inv.Resources = []cloud.Resource{
		{
			ID:   "gcp-instance",
			Type: "aws.ec2.instance",
			Properties: map[string]any{
				"public_ip": "203.0.113.10",
			},
		},
	}

	report := NewReport()
	RunAWSChecks(&report, inv)

	if len(report.Findings) != 0 {
		t.Errorf("expected AWS checks to ignore GCP inventory, got %+v", report.Findings)
	}
}

func TestRunAWSChecksMissingCoverage(t *testing.T) {
	inv := cloud.Inventory{
		Provider: cloud.ProviderAWS,
		Resources: []cloud.Resource{
			{
				ID:   "i-public",
				Type: "aws.ec2.instance",
				Properties: map[string]any{
					"public_ip": "203.0.113.10",
				},
			},
		},
	}

	report := NewReport()
	RunAWSChecks(&report, inv)

	if len(report.Findings) != 0 {
		t.Errorf("expected no findings without coverage evidence, got %+v", report.Findings)
	}
}

func TestRunAWSChecksNilReport(t *testing.T) {
	inv := awsTestInventory(cloud.CoverageCompleted)
	inv.Resources = []cloud.Resource{
		{
			ID:   "i-public",
			Type: "aws.ec2.instance",
			Properties: map[string]any{
				"public_ip": "203.0.113.10",
			},
		},
	}

	RunAWSChecks(nil, inv)
}
