package appsec

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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

	snykOutput, parseErr := parseSnykJSON(output)
	if parseErr != nil {
		result.Error = strings.TrimSpace(string(output))
		if result.Error == "" {
			result.Error = parseErr.Error()
		}

		if commandErr != nil {
			return result, fmt.Errorf(
				"Snyk scan failed: %w (invalid JSON output: %v)",
				commandErr,
				parseErr,
			)
		}

		return result, parseErr
	}

	result.Vulnerabilities = normalizeSnykVulnerabilities(snykOutput)

	if !isSuccessfulSnykExit(commandErr, len(result.Vulnerabilities)) {
		result.Error = strings.TrimSpace(string(output))

		if result.Error == "" {
			var exitErr *exec.ExitError
			if errors.As(commandErr, &exitErr) {
				result.Error = strings.TrimSpace(string(exitErr.Stderr))
			}
		}

		if result.Error == "" {
			result.Error = commandErr.Error()
		}

		return result, fmt.Errorf("Snyk scan failed: %w", commandErr)
	}

	result.Success = true
	return result, nil
}

// isSuccessfulSnykExit accepts normal success (exit code 0) and
// Snyk's vulnerability-found exit code (1) when findings are present.
func isSuccessfulSnykExit(commandErr error, vulnerabilityCount int) bool {
	if commandErr == nil {
		return true
	}

	var exitErr *exec.ExitError
	return errors.As(commandErr, &exitErr) &&
		exitErr.ExitCode() == 1 &&
		vulnerabilityCount > 0
}

type snykJSON struct {
	Vulnerabilities []snykVulnerability `json:"vulnerabilities"`
}

// parseSnykJSON requires an explicit vulnerabilities array. A missing or null
// field must never be interpreted as a clean scan.
func parseSnykJSON(output []byte) (snykJSON, error) {
	var envelope struct {
		Vulnerabilities json.RawMessage `json:"vulnerabilities"`
	}

	if err := json.Unmarshal(output, &envelope); err != nil {
		return snykJSON{}, fmt.Errorf("unable to parse Snyk JSON output: %w", err)
	}

	raw := bytes.TrimSpace(envelope.Vulnerabilities)
	if len(raw) == 0 {
		return snykJSON{}, fmt.Errorf(
			"invalid Snyk JSON output: missing vulnerabilities array",
		)
	}

	if raw[0] != '[' {
		return snykJSON{}, fmt.Errorf(
			"invalid Snyk JSON output: vulnerabilities must be an array",
		)
	}

	var entries []json.RawMessage
	if err := json.Unmarshal(raw, &entries); err != nil {
		return snykJSON{}, fmt.Errorf(
			"invalid Snyk vulnerabilities array: %w",
			err,
		)
	}

	vulnerabilities := make([]snykVulnerability, 0, len(entries))

	for i, entry := range entries {
		entry = bytes.TrimSpace(entry)

		if len(entry) == 0 || entry[0] != '{' {
			return snykJSON{}, fmt.Errorf(
				"invalid Snyk vulnerability at index %d: expected an object",
				i,
			)
		}

		var vulnerability snykVulnerability
		if err := json.Unmarshal(entry, &vulnerability); err != nil {
			return snykJSON{}, fmt.Errorf(
				"invalid Snyk vulnerability at index %d: %w",
				i,
				err,
			)
		}

		if strings.TrimSpace(vulnerability.Severity) == "" {
			return snykJSON{}, fmt.Errorf(
				"invalid Snyk vulnerability at index %d: missing severity",
				i,
			)
		}

		vulnerabilities = append(vulnerabilities, vulnerability)
	}

	return snykJSON{Vulnerabilities: vulnerabilities}, nil
}

type snykVulnerability struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`
	PackageName string   `json:"name"`
	Version     string   `json:"version"`
	FixedIn     []string `json:"fixedIn"`
	Description string   `json:"description"`
	From        []string `json:"from"`
	References  []struct {
		URL string `json:"url"`
	} `json:"references"`
}

func normalizeSnykVulnerabilities(
	input snykJSON,
) []Vulnerability {
	type vulnerabilityKey struct {
		ID               string
		PackageName      string
		Version          string
		FallbackTitle    string
		FallbackSeverity string
	}

	vulnerabilities := make([]Vulnerability, 0, len(input.Vulnerabilities))
	seen := make(map[vulnerabilityKey]int)

	for _, item := range input.Vulnerabilities {
		key := vulnerabilityKey{
			ID:          item.ID,
			PackageName: item.PackageName,
			Version:     item.Version,
		}

		// If the advisory ID is missing, use title and severity
		// as additional identity fields to avoid unrelated merges.
		if key.ID == "" {
			key.FallbackTitle = item.Title
			key.FallbackSeverity = strings.ToLower(item.Severity)
		}

		var fixedVersion string
		if len(item.FixedIn) > 0 {
			fixedVersion = item.FixedIn[0]
		}

		references := make([]string, 0, len(item.References))
		for _, reference := range item.References {
			if reference.URL != "" {
				references = mergeUniqueStrings(references, []string{reference.URL})
			}
		}

		if index, exists := seen[key]; exists {
			existing := &vulnerabilities[index]

			if existing.FixedVersion == "" {
				existing.FixedVersion = fixedVersion
			}
			if existing.Description == "" {
				existing.Description = item.Description
			}

			existing.References = mergeUniqueStrings(
				existing.References,
				references,
			)

			if len(item.From) > 0 {
				if existing.Evidence == nil {
					existing.Evidence = make(map[string]any)
				}

				paths, _ := existing.Evidence["dependency_paths"].([][]string)
				existing.Evidence["dependency_paths"] = mergeDependencyPath(
					paths,
					item.From,
				)
			}

			continue
		}

		evidence := make(map[string]any)
		if len(item.From) > 0 {
			evidence["dependency_paths"] = [][]string{
				append([]string(nil), item.From...),
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
			Evidence:       evidence,
		})

		seen[key] = len(vulnerabilities) - 1
	}

	return vulnerabilities
}

func mergeUniqueStrings(existing, incoming []string) []string {
	for _, candidate := range incoming {
		if candidate == "" {
			continue
		}

		found := false
		for _, current := range existing {
			if current == candidate {
				found = true
				break
			}
		}

		if !found {
			existing = append(existing, candidate)
		}
	}

	return existing
}

func mergeDependencyPath(existing [][]string, incoming []string) [][]string {
	for _, current := range existing {
		if equalStringSlices(current, incoming) {
			return existing
		}
	}

	return append(existing, append([]string(nil), incoming...))
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}
