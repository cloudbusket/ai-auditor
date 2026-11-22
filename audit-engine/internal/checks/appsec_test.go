package checks

import (
	"context"
	"errors"
	"strings"
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

	if len(report.Findings) != 0 {
		t.Fatalf("expected 0 findings for skipped scan, got %d", len(report.Findings))
	}

	if len(report.Modules) != 1 {
		t.Fatalf("expected 1 module, got %d", len(report.Modules))
	}

	if report.Modules[0].Name != "appsec" {
		t.Errorf("expected appsec module, got %s", report.Modules[0].Name)
	}

	if report.Modules[0].Status != ModuleSkipped {
		t.Errorf("expected module skipped, got %s", report.Modules[0].Status)
	}

	if report.Summary.Passed != 0 {
		t.Errorf("expected 0 passed checks, got %d", report.Summary.Passed)
	}

	if report.OverallStatus != StatusPass {
		t.Errorf("expected overall status pass when optional scan is skipped, got %s", report.OverallStatus)
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

	if len(report.Modules) != 1 || report.Modules[0].Status != ModuleFailed {
		t.Errorf("expected one failed appsec module, got %+v", report.Modules)
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

func TestRunAppSecChecksCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Scanner is unavailable deliberately. The cancelled context
	// must be detected before the availability check.
	scanner := &mockAppSecScanner{available: false}

	report := RunAppSecChecks(
		ctx,
		scanner,
		appsec.ScannerConfig{TargetPath: "/tmp/project"},
	)

	if len(report.Modules) != 1 {
		t.Fatalf("expected 1 module, got %d", len(report.Modules))
	}

	if report.Modules[0].Status != ModuleFailed {
		t.Errorf("expected module failed, got %s", report.Modules[0].Status)
	}

	if len(report.Findings) != 1 {
		t.Fatalf("expected 1 cancellation finding, got %d", len(report.Findings))
	}

	if report.Findings[0].Status != StatusError {
		t.Errorf("expected error finding, got %s", report.Findings[0].Status)
	}

	if report.OverallStatus != StatusError {
		t.Errorf("expected overall error, got %s", report.OverallStatus)
	}
}

func TestRunAppSecChecksMissingAdvisoryIDHasStableFingerprint(t *testing.T) {
	vulnerability := appsec.Vulnerability{
		Title:          "Missing advisory identifier",
		Severity:       "high",
		PackageName:    "example-package",
		PackageVersion: "1.2.3",
	}

	run := func(vulnerabilities []appsec.Vulnerability) Finding {
		scanner := &mockAppSecScanner{
			available: true,
			result: appsec.ScanResult{
				Scanner:         "snyk",
				TargetPath:      "/tmp/project",
				Success:         true,
				Vulnerabilities: vulnerabilities,
			},
		}

		report := RunAppSecChecks(
			context.Background(),
			scanner,
			appsec.ScannerConfig{TargetPath: "/tmp/project"},
		)
		report.Normalize()

		for _, finding := range report.Findings {
			if finding.Message == vulnerability.Title {
				return finding
			}
		}

		t.Fatalf("finding %q not found", vulnerability.Title)
		return Finding{}
	}

	first := run([]appsec.Vulnerability{vulnerability})

	second := run([]appsec.Vulnerability{
		{
			ID:          "OTHER-ADVISORY",
			Title:       "Another vulnerability",
			Severity:    "medium",
			PackageName: "other-package",
		},
		vulnerability,
	})

	if first.ID != second.ID {
		t.Errorf("finding ID changed: %q != %q", first.ID, second.ID)
	}

	if first.Fingerprint == "" {
		t.Fatal("expected a non-empty fingerprint")
	}

	if first.Fingerprint != second.Fingerprint {
		t.Errorf(
			"fingerprint changed with result ordering: %q != %q",
			first.Fingerprint,
			second.Fingerprint,
		)
	}

	if !strings.HasPrefix(first.ID, "APPSEC-VULN-UNKNOWN-") {
		t.Errorf("expected UNKNOWN fallback ID, got %q", first.ID)
	}
}
