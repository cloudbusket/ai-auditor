package remediation

import (
	"context"
	"errors"
)

var (
	ErrProviderUnavailable = errors.New("AI provider unavailable")
	ErrInvalidResponse     = errors.New("invalid AI remediation response")
)

// Provider defines the common interface for AI remediation providers.
//
// Implementations may support OpenAI, Anthropic, Gemini or other
// compatible AI services.
type Provider interface {
	Name() string

	Available(ctx context.Context) bool

	Generate(
		ctx context.Context,
		request RemediationRequest,
	) (RemediationSolution, error)
}
