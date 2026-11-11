package remediation

import (
	"time"

	"github.com/cloudbusket/ai-auditor/audit-engine/internal/checks"
)

// RemediationRequest contains the finding and relevant context
// provided to an AI remediation provider.
type RemediationRequest struct {
	Finding checks.Finding `json:"finding"`

	// AdditionalContext should contain only relevant, sanitized context.
	AdditionalContext string `json:"additional_context,omitempty"`
}

// RemediationStep describes one recommended remediation action.
type RemediationStep struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Command     string `json:"command,omitempty"`
	Impact      string `json:"impact,omitempty"`
}

// RemediationSolution is the structured AI-generated recommendation.
// It is advisory and must never be executed automatically.
type RemediationSolution struct {
	Provider     string            `json:"provider"`
	Model        string            `json:"model,omitempty"`
	GeneratedAt  time.Time         `json:"generated_at"`
	Summary      string            `json:"summary"`
	RootCause    string            `json:"root_cause"`
	Risk         string            `json:"risk"`
	Steps        []RemediationStep `json:"steps"`
	Verification []string          `json:"verification"`
	Rollback     []string          `json:"rollback"`
	Assumptions  []string          `json:"assumptions,omitempty"`
	Confidence   string            `json:"confidence"`
	AdvisoryOnly bool              `json:"advisory_only"`
}
