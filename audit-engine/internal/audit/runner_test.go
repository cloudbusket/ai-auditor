package audit

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/cloudbusket/ai-auditor/audit-engine/internal/appsec"
	"github.com/cloudbusket/ai-auditor/audit-engine/internal/checks"
	"github.com/cloudbusket/ai-auditor/audit-engine/internal/cloud"
)

type testAppSecScanner struct{}

func (s *testAppSecScanner) Name() string {
	return "test"
}

func (s *testAppSecScanner) Available(context.Context) bool {
	return false
}

func (s *testAppSecScanner) Scan(
	context.Context,
	appsec.ScannerConfig,
) (appsec.ScanResult, error) {
	return appsec.ScanResult{}, nil
}

type testCloudCollector struct {
	inventory cloud.Inventory
	err       error
	calls     int
}

func (c *testCloudCollector) Discover(
	_ context.Context,
	_ cloud.Config,
) (cloud.Inventory, error) {
	c.calls++
	return c.inventory, c.err
}

func findModule(t *testing.T, report checks.Report, name string) checks.ModuleResult {
	t.Helper()

	for _, module := range report.Modules {
		if module.Name == name {
			return module
		}
	}

	t.Fatalf("module %q not found", name)
	return checks.ModuleResult{}
}

func TestRunWithoutCloudConfiguration(t *testing.T) {
	collector := &testCloudCollector{}

	report := Run(
		context.Background(),
		&testAppSecScanner{},
		Config{TargetPath: "."},
	)

	if collector.calls != 0 {
		t.Fatalf("expected no cloud collector calls, got %d", collector.calls)
	}

	if report.CloudInventory != nil {
		t.Fatal("expected no cloud inventory when cloud discovery is not configured")
	}

	for _, module := range report.Modules {
		if module.Name == "cloud_discovery" {
			t.Fatal("cloud discovery module should not run without configuration")
		}
	}
}

func TestRunCloudDiscoverySuccess(t *testing.T) {
	collector := &testCloudCollector{
		inventory: cloud.Inventory{
			Provider:  cloud.ProviderGCP,
			ProjectID: "test-project",
			Resources: []cloud.Resource{
				{
					ID:        "projects/123",
					Name:      "test-project",
					Type:      "gcp.project",
					Provider:  cloud.ProviderGCP,
					ProjectID: "test-project",
				},
			},
			Coverage: []cloud.Coverage{
				{
					Provider:      cloud.ProviderGCP,
					Category:      "project_metadata",
					Status:        cloud.CoverageCompleted,
					ResourceCount: 1,
				},
			},
		},
	}

	report := Run(
		context.Background(),
		&testAppSecScanner{},
		Config{
			TargetPath:     ".",
			CloudCollector: collector,
			CloudConfig: cloud.Config{
				ProjectID: "test-project",
			},
		},
	)

	if collector.calls != 1 {
		t.Fatalf("expected one cloud discovery call, got %d", collector.calls)
	}

	if report.CloudInventory == nil {
		t.Fatal("expected cloud inventory in report")
	}

	if report.CloudInventory.ProjectID != "test-project" {
		t.Errorf("expected project test-project, got %q",
			report.CloudInventory.ProjectID)
	}

	if len(report.CloudInventory.Resources) != 1 {
		t.Errorf("expected one resource, got %d",
			len(report.CloudInventory.Resources))
	}

	if len(report.Coverage) != 1 {
		t.Fatalf("expected one coverage record, got %d", len(report.Coverage))
	}

	if report.Coverage[0].Category != "project_metadata" {
		t.Errorf("unexpected coverage category %q", report.Coverage[0].Category)
	}

	if report.Coverage[0].Status != checks.CoverageCompleted {
		t.Errorf("expected completed coverage, got %q", report.Coverage[0].Status)
	}

	module := findModule(t, report, "cloud_discovery")

	if module.Status != checks.ModuleCompleted {
		t.Errorf("expected completed module, got %q", module.Status)
	}
}

func TestRunCloudDiscoveryWithCoverageGap(t *testing.T) {
	collector := &testCloudCollector{
		inventory: cloud.Inventory{
			Provider:  cloud.ProviderGCP,
			ProjectID: "test-project",
			Coverage: []cloud.Coverage{
				{
					Provider: cloud.ProviderGCP,
					Category: "compute",
					Status:   cloud.CoveragePermissionDenied,
					Message:  "Permission denied",
				},
			},
		},
	}

	report := Run(
		context.Background(),
		&testAppSecScanner{},
		Config{
			CloudCollector: collector,
			CloudConfig: cloud.Config{
				ProjectID: "test-project",
			},
		},
	)

	module := findModule(t, report, "cloud_discovery")

	if module.Status != checks.ModuleCompleted {
		t.Errorf("expected completed discovery with coverage gaps, got %q",
			module.Status)
	}

	if !strings.Contains(module.Message, "coverage gaps") {
		t.Errorf("expected coverage-gap message, got %q", module.Message)
	}

	if len(report.Coverage) != 1 ||
		report.Coverage[0].Status != checks.CoveragePermissionDenied {
		t.Errorf("expected permission-denied coverage to be preserved: %+v",
			report.Coverage)
	}
}

func TestRunCloudDiscoveryErrorPreservesInventory(t *testing.T) {
	collector := &testCloudCollector{
		inventory: cloud.Inventory{
			Provider:  cloud.ProviderGCP,
			ProjectID: "test-project",
			Coverage: []cloud.Coverage{
				{
					Provider: cloud.ProviderGCP,
					Category: "project_metadata",
					Status:   cloud.CoverageError,
					Message:  "Project metadata request failed",
				},
			},
		},
		err: errors.New("cloud API request failed"),
	}

	report := Run(
		context.Background(),
		&testAppSecScanner{},
		Config{
			CloudCollector: collector,
			CloudConfig: cloud.Config{
				ProjectID: "test-project",
			},
		},
	)

	if report.CloudInventory == nil {
		t.Fatal("expected partial inventory to be preserved")
	}

	if report.CloudInventory.ProjectID != "test-project" {
		t.Errorf("expected project metadata to be preserved, got %q",
			report.CloudInventory.ProjectID)
	}

	if len(report.Coverage) != 1 {
		t.Fatalf("expected coverage information to be preserved, got %d records",
			len(report.Coverage))
	}

	module := findModule(t, report, "cloud_discovery")

	if module.Status != checks.ModuleFailed {
		t.Errorf("expected failed module, got %q", module.Status)
	}

	if !strings.Contains(module.Message, "cloud API request failed") {
		t.Errorf("expected discovery error in module message, got %q", module.Message)
	}
}

func TestRunCloudProjectWithoutCollector(t *testing.T) {
	report := Run(
		context.Background(),
		&testAppSecScanner{},
		Config{
			CloudConfig: cloud.Config{
				ProjectID: "test-project",
			},
		},
	)

	module := findModule(t, report, "cloud_discovery")

	if module.Status != checks.ModuleFailed {
		t.Errorf("expected failed module, got %q", module.Status)
	}

	if report.CloudInventory != nil {
		t.Error("expected no inventory without a collector")
	}
}
