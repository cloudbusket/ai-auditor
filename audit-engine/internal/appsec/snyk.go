package appsec

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// SnykScanner integrates the Snyk CLI with CloudBusket Auditor.
type SnykScanner struct{}

// Name returns the scanner identifier.
func (s *SnykScanner) Name() string {
	return "snyk"
}

// Available reports whether the Snyk CLI is installed.
func (s *SnykScanner) Available(ctx context.Context) bool {
	if err := ctx.Err(); err != nil {
		return false
	}

	_, err := exec.LookPath("snyk")
	return err == nil
}

// Scan executes a Snyk dependency test and normalizes its JSON output.
func (s *SnykScanner) Scan(
	ctx context.Context,
	config ScannerConfig,
) (ScanResult, error) {
	startedAt := time.Now()

	result := ScanResult{
		Scanner:         s.Name(),
		TargetPath:      config.TargetPath,
		StartedAt:       startedAt,
		Vulnerabilities: []Vulnerability{},
	}

	target := strings.TrimSpace(config.TargetPath)
	if target == "" {
		return result, fmt.Errorf("Snyk target path is required")
	}

	timeout := config.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}

	scanCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	snykPath, err := exec.LookPath("snyk")
	if err != nil {
		return result, fmt.Errorf("Snyk CLI is not installed")
	}

	cmd := exec.CommandContext(
		scanCtx,
		snykPath,
		"test",
		"--json",
		"--all-projects",
		"--",
	)

	cmd.Dir = target

	output, commandErr := cmd.Output()

	result.CompletedAt = time.Now()

	if scanCtx.Err() != nil {
		result.Error = scanCtx.Err().Error()
		return result, scanCtx.Err()
	}

	var snykOutput snykJSON

	if err := json.Unmarshal(output, &snykOutput); err != nil {
		if commandErr != nil {
			result.Error = strings.TrimSpace(string(output))
			return result, fmt.Errorf(
				"Snyk scan failed: %w",
				commandErr,
			)
		}

		return result, fmt.Errorf(
			"unable to parse Snyk JSON output: %w",
			err,
		)
	}

	result.Vulnerabilities = normalizeSnykVulnerabilities(snykOutput)

	if commandErr != nil && len(result.Vulnerabilities) == 0 {
		result.Error = strings.TrimSpace(string(output))
		return result, fmt.Errorf(
			"Snyk scan failed: %w",
			commandErr,
		)
	}

	result.Success = true
	return result, nil
}

type snykJSON struct {
	Vulnerabilities []snykVulnerability `json:"vulnerabilities"`
}

type snykVulnerability struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`
	PackageName string   `json:"name"`
	Version     string   `json:"version"`
	FixedIn     []string `json:"fixedIn"`
	Description string   `json:"description"`
	References  []struct {
		URL string `json:"url"`
	} `json:"references"`
}

func normalizeSnykVulnerabilities(
	input snykJSON,
) []Vulnerability {
	vulnerabilities := make(
		[]Vulnerability,
		0,
		len(input.Vulnerabilities),
	)

	for _, item := range input.Vulnerabilities {
		var fixedVersion string
		if len(item.FixedIn) > 0 {
			fixedVersion = item.FixedIn[0]
		}

		references := make([]string, 0, len(item.References))
		for _, reference := range item.References {
			if reference.URL != "" {
				references = append(references, reference.URL)
			}
		}

		vulnerabilities = append(vulnerabilities, Vulnerability{
			ID:             item.ID,
			Title:          item.Title,
			Severity:       strings.ToLower(item.Severity),
			PackageName:    item.PackageName,
			PackageVersion: item.Version,
			FixedVersion:   fixedVersion,
			Description:    item.Description,
			References:     references,
		})
	}

	return vulnerabilities
}
