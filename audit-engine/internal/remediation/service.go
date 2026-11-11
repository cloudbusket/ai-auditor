package remediation

import (
	"context"
	"fmt"
	"strings"
	"time"
)

const defaultTimeout = 60 * time.Second

// Service coordinates AI remediation generation.
type Service struct {
	provider Provider
	timeout  time.Duration
}

func NewService(provider Provider, timeout time.Duration) *Service {
	if timeout <= 0 {
		timeout = defaultTimeout
	}

	return &Service{
		provider: provider,
		timeout:  timeout,
	}
}

func (s *Service) Generate(
	ctx context.Context,
	request RemediationRequest,
) (RemediationSolution, error) {
	if s == nil || s.provider == nil {
		return RemediationSolution{}, ErrProviderUnavailable
	}

	if strings.TrimSpace(request.Finding.ID) == "" {
		return RemediationSolution{}, fmt.Errorf("finding ID is required")
	}

	if !s.provider.Available(ctx) {
		return RemediationSolution{}, ErrProviderUnavailable
	}

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	// Sanitize all provider-bound data.
	// The original finding in scan history remains unchanged.
	safeRequest := RemediationRequest{
		Finding:           sanitizeFinding(request.Finding),
		AdditionalContext: sanitizeAdditionalContext(request.AdditionalContext),
	}

	solution, err := s.provider.Generate(ctx, safeRequest)
	if err != nil {
		return RemediationSolution{}, fmt.Errorf(
			"generate remediation: %w", err,
		)
	}

	// Validate before sanitizing so oversized output is rejected,
	// rather than silently truncated.
	if err := validateRemediationSolution(solution); err != nil {
		return RemediationSolution{}, err
	}

	solution = sanitizeRemediationSolution(solution)

	// Recheck required fields after sanitization.
	if strings.TrimSpace(solution.Summary) == "" ||
		strings.TrimSpace(solution.RootCause) == "" {
		return RemediationSolution{}, ErrInvalidResponse
	}

	solution.Provider = s.provider.Name()
	solution.GeneratedAt = time.Now().UTC()
	solution.AdvisoryOnly = true

	return solution, nil
}
