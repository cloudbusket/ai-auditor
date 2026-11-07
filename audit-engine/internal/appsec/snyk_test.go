package appsec

import (
	"context"
	"testing"
)

func TestNormalizeSnykVulnerabilities(t *testing.T) {
	input := snykJSON{
		Vulnerabilities: []snykVulnerability{
			{
				ID:          "SNYK-GO-TEST-123",
				Title:       "Example vulnerability",
				Severity:    "HIGH",
				PackageName: "example-package",
				Version:     "1.0.0",
				FixedIn:     []string{"1.0.2"},
				Description: "Example vulnerability description",
				References: []struct {
					URL string `json:"url"`
				}{
					{URL: "https://example.com/advisory"},
				},
			},
		},
	}

	got := normalizeSnykVulnerabilities(input)

	if len(got) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(got))
	}

	v := got[0]

	if v.ID != "SNYK-GO-TEST-123" {
		t.Errorf("unexpected ID: %s", v.ID)
	}
	if v.Severity != "high" {
		t.Errorf("expected normalized severity 'high', got %q", v.Severity)
	}
	if v.PackageName != "example-package" {
		t.Errorf("unexpected package name: %s", v.PackageName)
	}
	if v.FixedVersion != "1.0.2" {
		t.Errorf("unexpected fixed version: %s", v.FixedVersion)
	}
	if len(v.References) != 1 {
		t.Errorf("expected 1 reference, got %d", len(v.References))
	}
}

func TestSnykScannerName(t *testing.T) {
	scanner := &SnykScanner{}

	if scanner.Name() != "snyk" {
		t.Fatalf("expected scanner name 'snyk', got %q", scanner.Name())
	}
}

func TestSnykScannerUnavailableWithCancelledContext(t *testing.T) {
	scanner := &SnykScanner{}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if scanner.Available(ctx) {
		t.Fatal("expected scanner to be unavailable with cancelled context")
	}
}
