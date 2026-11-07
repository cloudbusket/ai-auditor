package checks

import (
	"context"
	"errors"
	"testing"

	"github.com/cloudbusket/ai-auditor/audit-engine/internal/appsec"
)

type mockAppSecScanner struct {
	available bool
	result    appsec.ScanResult
	err       error
}

func (m *mockAppSecScanner) Name() string {
	return "snyk"
}

func (m *mockAppSecScanner) Available(ctx context.Context) bool {
	return m.available
}

func (m *mockAppSecScanner) Scan(
	ctx context.Context,
	config appsec.ScannerConfig,
) (appsec.ScanResult, error) {
	return m.result, m.err
}

func TestRunAppSecChecksScannerUnavailable(t *testing.T) {
	scanner := &mockAppSecScanner{available: false}

	report := RunAppSecChecks(
		context.Background(),
		scanner,
		appsec.ScannerConfig{TargetPath: "/tmp/project"},
	)

	if len(report.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(report.Findings))
	}

	if report.Findings[0].Status != StatusPass {
		t.Errorf("expected pass, got %s", report.Findings[0].Status)
	}
}

func TestRunAppSecChecksScanError(t *testing.T) {
	scanner := &mockAppSecScanner{
		available: true,
		err:       errors.New("authentication failed"),
	}

	report := RunAppSecChecks(
		context.Background(),
		scanner,
		appsec.ScannerConfig{TargetPath: "/tmp/project"},
	)

	if report.OverallStatus != StatusError {
		t.Errorf("expected error, got %s", report.OverallStatus)
	}
}

func TestRunAppSecChecksCleanScan(t *testing.T) {
	scanner := &mockAppSecScanner{
		available: true,
		result: appsec.ScanResult{
			Scanner:    "snyk",
			TargetPath: "/tmp/project",
			Success:    true,
		},
	}

	report := RunAppSecChecks(
		context.Background(),
		scanner,
		appsec.ScannerConfig{TargetPath: "/tmp/project"},
	)

	if len(report.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(report.Findings))
	}

	if report.Findings[0].Status != StatusPass {
		t.Errorf("expected pass, got %s", report.Findings[0].Status)
	}
}

func TestRunAppSecChecksVulnerabilityMapping(t *testing.T) {
	scanner := &mockAppSecScanner{
		available: true,
		result: appsec.ScanResult{
			Scanner:    "snyk",
			TargetPath: "/tmp/project",
			Success:    true,
			Vulnerabilities: []appsec.Vulnerability{
				{
					ID:             "TEST-CRITICAL",
					Title:          "Critical vulnerability",
					Severity:       "critical",
					PackageName:    "package-a",
					PackageVersion: "1.0.0",
				},
				{
					ID:          "TEST-HIGH",
					Title:       "High vulnerability",
					Severity:    "high",
					PackageName: "package-b",
				},
				{
					ID:       "TEST-MEDIUM",
					Title:    "Medium vulnerability",
					Severity: "medium",
				},
				{
					ID:       "TEST-LOW",
					Title:    "Low vulnerability",
					Severity: "low",
				},
			},
		},
	}

	report := RunAppSecChecks(
		context.Background(),
		scanner,
		appsec.ScannerConfig{TargetPath: "/tmp/project"},
	)

	if len(report.Findings) != 4 {
		t.Fatalf("expected 4 findings, got %d", len(report.Findings))
	}

	expected := []Status{
		StatusCritical,
		StatusCritical,
		StatusWarning,
		StatusWarning,
	}

	for i, finding := range report.Findings {
		if finding.Status != expected[i] {
			t.Errorf(
				"finding %d: expected %s, got %s",
				i,
				expected[i],
				finding.Status,
			)
		}

		if finding.Source != "snyk" {
			t.Errorf("expected source snyk, got %s", finding.Source)
		}
	}

	if report.Summary.Critical != 2 {
		t.Errorf("expected 2 critical findings, got %d", report.Summary.Critical)
	}

	if report.Summary.Warnings != 2 {
		t.Errorf("expected 2 warnings, got %d", report.Summary.Warnings)
	}
}
