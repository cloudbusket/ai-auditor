package checks

import "time"

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
	GeneratedAt   time.Time      `json:"generated_at"`
	OverallStatus Status         `json:"overall_status"`
	Summary       Summary        `json:"summary"`
	Modules       []ModuleResult `json:"modules"`
	Findings      []Finding      `json:"findings"`
}

func NewReport() Report {
	return Report{
		GeneratedAt:   time.Now().UTC(),
		OverallStatus: StatusPass,
		Modules:       []ModuleResult{},
		Findings:      []Finding{},
	}
}

func (r *Report) AddModule(module ModuleResult) {
	r.Modules = append(r.Modules, module)
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
