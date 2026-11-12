package cloud

import (
	"context"
	"time"
)

// Provider identifies a supported cloud platform.
type Provider string

const (
	ProviderGCP   Provider = "gcp"
	ProviderAWS   Provider = "aws"
	ProviderAzure Provider = "azure"
)

// CoverageStatus describes the outcome of a collection operation.
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

// Resource represents a normalized cloud resource.
type Resource struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Type       string            `json:"type"`
	Provider   Provider          `json:"provider"`
	ProjectID  string            `json:"project_id,omitempty"`
	Region     string            `json:"region,omitempty"`
	Zone       string            `json:"zone,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
	Properties map[string]any    `json:"properties,omitempty"`
}

// Coverage describes the collection result for one resource category.
type Coverage struct {
	Provider      Provider       `json:"provider"`
	Category      string         `json:"category"`
	Status        CoverageStatus `json:"status"`
	ResourceCount int64          `json:"resource_count"`
	Message       string         `json:"message,omitempty"`
	StartedAt     time.Time      `json:"started_at,omitempty"`
	CompletedAt   time.Time      `json:"completed_at,omitempty"`
	DurationMs    int64          `json:"duration_ms,omitempty"`
}

// Inventory contains normalized resources discovered in a cloud account.
type Inventory struct {
	Provider  Provider   `json:"provider"`
	AccountID string     `json:"account_id,omitempty"`
	ProjectID string     `json:"project_id,omitempty"`
	Resources []Resource `json:"resources"`
	Coverage  []Coverage `json:"coverage"`
}

// Config controls a cloud discovery operation.
type Config struct {
	ProjectID string
	Timeout   time.Duration
}

// Collector is implemented by each cloud provider.
type Collector interface {
	Discover(ctx context.Context, config Config) (Inventory, error)
}
