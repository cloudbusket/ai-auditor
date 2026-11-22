package appsec

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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

func TestNormalizeSnykVulnerabilitiesDeduplicatesDependencyPaths(t *testing.T) {
	input := snykJSON{
		Vulnerabilities: []snykVulnerability{
			{
				ID:          "SNYK-GOLANG-TEST-123",
				Title:       "Example vulnerability",
				Severity:    "CRITICAL",
				PackageName: "example-package",
				Version:     "1.0.0",
				FixedIn:     []string{"1.0.2"},
				From:        []string{"root", "module-a", "example-package@1.0.0"},
			},
			{
				ID:          "SNYK-GOLANG-TEST-123",
				Title:       "Example vulnerability",
				Severity:    "CRITICAL",
				PackageName: "example-package",
				Version:     "1.0.0",
				FixedIn:     []string{"1.0.2"},
				From:        []string{"root", "module-b", "example-package@1.0.0"},
			},
			{
				ID:          "SNYK-GOLANG-TEST-123",
				Title:       "Example vulnerability",
				Severity:    "CRITICAL",
				PackageName: "example-package",
				Version:     "1.0.0",
				FixedIn:     []string{"1.0.2"},
				From:        []string{"root", "module-a", "example-package@1.0.0"},
			},
			{
				ID:          "SNYK-GOLANG-TEST-123",
				Title:       "Example vulnerability",
				Severity:    "CRITICAL",
				PackageName: "example-package",
				Version:     "1.0.1",
				FixedIn:     []string{"1.0.2"},
				From:        []string{"root", "module-c", "example-package@1.0.1"},
			},
		},
	}

	got := normalizeSnykVulnerabilities(input)

	if len(got) != 2 {
		t.Fatalf("expected 2 unique vulnerabilities, got %d", len(got))
	}

	first := got[0]

	if first.FixedVersion != "1.0.2" {
		t.Errorf("expected fixed version 1.0.2, got %q", first.FixedVersion)
	}

	paths, ok := first.Evidence["dependency_paths"].([][]string)
	if !ok {
		t.Fatal("expected dependency_paths evidence to be [][]string")
	}

	if len(paths) != 2 {
		t.Errorf("expected 2 unique dependency paths, got %d", len(paths))
	}
}

func TestIsSuccessfulSnykExit(t *testing.T) {
	tests := []struct {
		name               string
		exitCode           int
		vulnerabilityCount int
		want               bool
	}{
		{
			name:               "exit 0 with no findings",
			exitCode:           0,
			vulnerabilityCount: 0,
			want:               true,
		},
		{
			name:               "exit 0 with findings",
			exitCode:           0,
			vulnerabilityCount: 2,
			want:               true,
		},
		{
			name:               "exit 1 with findings",
			exitCode:           1,
			vulnerabilityCount: 2,
			want:               true,
		},
		{
			name:               "exit 1 without findings",
			exitCode:           1,
			vulnerabilityCount: 0,
			want:               false,
		},
		{
			name:               "exit 2 with findings",
			exitCode:           2,
			vulnerabilityCount: 2,
			want:               false,
		},
		{
			name:               "exit 2 without findings",
			exitCode:           2,
			vulnerabilityCount: 0,
			want:               false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var commandErr error

			if tt.exitCode != 0 {
				commandErr = exec.Command(
					"sh",
					"-c",
					fmt.Sprintf("exit %d", tt.exitCode),
				).Run()
			}

			got := isSuccessfulSnykExit(
				commandErr,
				tt.vulnerabilityCount,
			)

			if got != tt.want {
				t.Errorf("isSuccessfulSnykExit() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSnykScannerScanWithFakeCLI(t *testing.T) {
	tests := []struct {
		name         string
		exitCode     int
		output       string
		wantSuccess  bool
		wantFindings int
		wantError    bool
	}{
		{
			name:         "clean scan",
			exitCode:     0,
			output:       `{"vulnerabilities":[]}`,
			wantSuccess:  true,
			wantFindings: 0,
		},
		{
			name:         "vulnerabilities found",
			exitCode:     1,
			output:       `{"vulnerabilities":[{"id":"TEST-123","title":"Test vulnerability","severity":"high","name":"test-package","version":"1.0.0"}]}`,
			wantSuccess:  true,
			wantFindings: 1,
		},
		{
			name:         "execution failure despite partial findings",
			exitCode:     2,
			output:       `{"vulnerabilities":[{"id":"TEST-123","title":"Test vulnerability","severity":"high","name":"test-package","version":"1.0.0"}]}`,
			wantSuccess:  false,
			wantFindings: 1,
			wantError:    true,
		},
		{
			name:        "malformed JSON",
			exitCode:    0,
			output:      `{invalid-json`,
			wantSuccess: false,
			wantError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			binDir := t.TempDir()
			targetDir := t.TempDir()

			script := fmt.Sprintf(
				"#!/bin/sh\ncat <<'SNYK_JSON'\n%s\nSNYK_JSON\nexit %d\n",
				tt.output,
				tt.exitCode,
			)

			snykPath := filepath.Join(binDir, "snyk")
			if err := os.WriteFile(snykPath, []byte(script), 0755); err != nil {
				t.Fatalf("create fake Snyk CLI: %v", err)
			}

			t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

			scanner := &SnykScanner{}
			result, err := scanner.Scan(context.Background(), ScannerConfig{
				TargetPath: targetDir,
			})

			if (err != nil) != tt.wantError {
				t.Fatalf("Scan() error = %v, wantError %v", err, tt.wantError)
			}

			if result.Success != tt.wantSuccess {
				t.Errorf("Success = %v, want %v", result.Success, tt.wantSuccess)
			}

			if len(result.Vulnerabilities) != tt.wantFindings {
				t.Errorf(
					"finding count = %d, want %d",
					len(result.Vulnerabilities),
					tt.wantFindings,
				)
			}
		})
	}
}
