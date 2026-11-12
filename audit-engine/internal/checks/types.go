package checks

import (
	"time"

	"github.com/cloudbusket/ai-auditor/audit-engine/internal/cloud"
)

type Status string

const (
	StatusPass     Status = "pass"
	StatusWarning  Status = "warning"
	StatusCritical Status = "critical"
	StatusError    Status = "error"
)

type ModuleStatus string

const (
	ModuleCompleted ModuleStatus = "completed"
	ModuleSkipped   ModuleStatus = "skipped"
	ModuleFailed    ModuleStatus = "failed"
)

// CoverageStatus describes the completeness of data collection.
type CoverageStatus string

const (
	CoverageCompleted        CoverageStatus = "completed"
	CoveragePartial          CoverageStatus = "partial"
	CoveragePermissionDenied CoverageStatus = "permission_denied"
	CoverageAPIDisabled      CoverageStatus = "api_disabled"
	CoverageNotConfigured    CoverageStatus = "not_configured"
	CoverageNoData           CoverageStatus = "no_data"
	CoverageUnsupported      CoverageStatus = "unsupported"
	CoverageError            CoverageStatus = "error"
)

// Coverage records the collection outcome for a provider resource category.
type Coverage struct {
	Provider      string         `json:"provider"`
	Category      string         `json:"category"`
	Status        CoverageStatus `json:"status"`
	ResourceCount int64          `json:"resource_count"`
	Message       string         `json:"message,omitempty"`
	StartedAt     time.Time      `json:"started_at,omitempty"`
	CompletedAt   time.Time      `json:"completed_at,omitempty"`
	DurationMs    int64          `json:"duration_ms,omitempty"`
}

type ModuleResult struct {
	Name        string       `json:"name"`
	Status      ModuleStatus `json:"status"`
	Message     string       `json:"message,omitempty"`
	StartedAt   time.Time    `json:"started_at"`
	CompletedAt time.Time    `json:"completed_at"`
	DurationMs  int64        `json:"duration_ms"`
}

type Finding struct {
	ID             string         `json:"id"`
	Source         string         `json:"source"`
	Category       string         `json:"category"`
	Asset          string         `json:"asset,omitempty"`
	Status         Status         `json:"status"`
	Severity       string         `json:"severity"`
	Message        string         `json:"message"`
	Description    string         `json:"description,omitempty"`
	Recommendation string         `json:"recommendation,omitempty"`
	Evidence       map[string]any `json:"evidence,omitempty"`
}

type Summary struct {
	Passed   int `json:"passed"`
	Warnings int `json:"warnings"`
	Critical int `json:"critical"`
	Errors   int `json:"errors"`
}

type Report struct {
	GeneratedAt    time.Time        `json:"generated_at"`
	OverallStatus  Status           `json:"overall_status"`
	Summary        Summary          `json:"summary"`
	Modules        []ModuleResult   `json:"modules"`
	Coverage       []Coverage       `json:"coverage"`
	CloudInventory *cloud.Inventory `json:"cloud_inventory,omitempty"`
	Findings       []Finding        `json:"findings"`
}

func NewReport() Report {
	return Report{
		GeneratedAt:   time.Now().UTC(),
		OverallStatus: StatusPass,
		Modules:       []ModuleResult{},
		Coverage:      []Coverage{},
		Findings:      []Finding{},
	}
}

func (r *Report) AddModule(module ModuleResult) {
	r.Modules = append(r.Modules, module)
}

func (r *Report) AddCoverage(coverage Coverage) {
	r.Coverage = append(r.Coverage, coverage)
}

func (r *Report) Add(f Finding) {
	if f.Source == "" {
		f.Source = "native"
	}

	r.Findings = append(r.Findings, f)

	switch f.Status {
	case StatusPass:
		r.Summary.Passed++
	case StatusWarning:
		r.Summary.Warnings++
	case StatusCritical:
		r.Summary.Critical++
	case StatusError:
		r.Summary.Errors++
	}

	switch f.Status {
	case StatusError:
		r.OverallStatus = StatusError
	case StatusCritical:
		if r.OverallStatus != StatusError {
			r.OverallStatus = StatusCritical
		}
	case StatusWarning:
		if r.OverallStatus == StatusPass {
			r.OverallStatus = StatusWarning
		}
	}
}
