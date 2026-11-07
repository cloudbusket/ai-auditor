package appsec

import "context"

// Scanner defines the common interface for application security scanners.
type Scanner interface {
	Name() string
	Available(ctx context.Context) bool
	Scan(ctx context.Context, config ScannerConfig) (ScanResult, error)
}
