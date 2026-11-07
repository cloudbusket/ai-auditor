package appsec

import "time"

// ScannerConfig defines the configuration for an application security scan.
type ScannerConfig struct {
	TargetPath string
	Timeout    time.Duration
}

// Vulnerability represents a security issue reported by a scanner.
type Vulnerability struct {
	ID             string         `json:"id"`
	Title          string         `json:"title"`
	Severity       string         `json:"severity"`
	PackageName    string         `json:"package_name,omitempty"`
	PackageVersion string         `json:"package_version,omitempty"`
	FixedVersion   string         `json:"fixed_version,omitempty"`
	Asset          string         `json:"asset,omitempty"`
	Description    string         `json:"description,omitempty"`
	Recommendation string         `json:"recommendation,omitempty"`
	References     []string       `json:"references,omitempty"`
	Evidence       map[string]any `json:"evidence,omitempty"`
}

// ScanResult contains the normalized output from an external scanner.
type ScanResult struct {
	Scanner         string          `json:"scanner"`
	TargetPath      string          `json:"target_path"`
	StartedAt       time.Time       `json:"started_at"`
	CompletedAt     time.Time       `json:"completed_at"`
	Success         bool            `json:"success"`
	Error           string          `json:"error,omitempty"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}
