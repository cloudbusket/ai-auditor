package checks

import "time"

type Status string

const (
	StatusPass     Status = "pass"
	StatusWarning  Status = "warning"
	StatusCritical Status = "critical"
	StatusError    Status = "error"
)

type Finding struct {
	ID             string `json:"id"`
	Category       string `json:"category"`
	Status         Status `json:"status"`
	Severity       string `json:"severity"`
	Message        string `json:"message"`
	Recommendation string `json:"recommendation,omitempty"`
}

type Summary struct {
	Passed   int `json:"passed"`
	Warnings int `json:"warnings"`
	Critical int `json:"critical"`
	Errors   int `json:"errors"`
}

type Report struct {
	GeneratedAt   time.Time `json:"generated_at"`
	OverallStatus Status    `json:"overall_status"`
	Summary       Summary   `json:"summary"`
	Findings      []Finding `json:"findings"`
}

func NewReport() Report {
	return Report{
		GeneratedAt:   time.Now().UTC(),
		OverallStatus: StatusPass,
		Findings:      []Finding{},
	}
}

func (r *Report) Add(f Finding) {
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
