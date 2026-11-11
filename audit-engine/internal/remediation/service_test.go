package remediation

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cloudbusket/ai-auditor/audit-engine/internal/checks"
)

type mockProvider struct {
	available bool
	solution  RemediationSolution
	err       error
	called    bool
	request   RemediationRequest
}

func (m *mockProvider) Name() string {
	return "mock"
}

func (m *mockProvider) Available(context.Context) bool {
	return m.available
}

func (m *mockProvider) Generate(
	ctx context.Context,
	request RemediationRequest,
) (RemediationSolution, error) {
	m.called = true
	m.request = request

	if m.err != nil {
		return RemediationSolution{}, m.err
	}

	select {
	case <-ctx.Done():
		return RemediationSolution{}, ctx.Err()
	default:
		return m.solution, nil
	}
}

func validRequest() RemediationRequest {
	return RemediationRequest{
		Finding: checks.Finding{
			ID:      "DISK001",
			Message: "Root disk usage is high",
		},
	}
}

func TestServiceRejectsMissingProvider(t *testing.T) {
	service := NewService(nil, time.Second)

	_, err := service.Generate(context.Background(), validRequest())

	if !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("expected ErrProviderUnavailable, got %v", err)
	}
}

func TestServiceRejectsFindingWithoutID(t *testing.T) {
	provider := &mockProvider{available: true}
	service := NewService(provider, time.Second)

	request := validRequest()
	request.Finding.ID = ""

	_, err := service.Generate(context.Background(), request)

	if err == nil {
		t.Fatal("expected an error for a finding without an ID")
	}

	if provider.called {
		t.Fatal("provider should not be called for an invalid finding")
	}
}

func TestServiceRejectsUnavailableProvider(t *testing.T) {
	provider := &mockProvider{available: false}
	service := NewService(provider, time.Second)

	_, err := service.Generate(context.Background(), validRequest())

	if !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("expected ErrProviderUnavailable, got %v", err)
	}

	if provider.called {
		t.Fatal("unavailable provider should not be called")
	}
}

func TestServiceMarksSolutionAdvisoryOnly(t *testing.T) {
	provider := &mockProvider{
		available: true,
		solution: RemediationSolution{
			Summary:    "Reduce root disk usage",
			RootCause:  "Disk space is nearly exhausted",
			Confidence: "high",
			Steps: []RemediationStep{
				{
					Title:       "Review large files",
					Description: "Identify large files and directories consuming root filesystem space.",
				},
			},
		},
	}

	service := NewService(provider, time.Second)

	solution, err := service.Generate(context.Background(), validRequest())
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	if !solution.AdvisoryOnly {
		t.Error("expected AdvisoryOnly to be true")
	}

	if solution.Provider != "mock" {
		t.Errorf("expected provider mock, got %q", solution.Provider)
	}

	if solution.GeneratedAt.IsZero() {
		t.Error("expected GeneratedAt to be set")
	}

	if solution.Summary != "Reduce root disk usage" {
		t.Errorf("unexpected summary: %q", solution.Summary)
	}
}

func TestServiceRejectsIncompleteSolution(t *testing.T) {
	provider := &mockProvider{
		available: true,
		solution: RemediationSolution{
			Summary: "A summary without a root cause",
		},
	}

	service := NewService(provider, time.Second)

	_, err := service.Generate(context.Background(), validRequest())

	if !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("expected ErrInvalidResponse, got %v", err)
	}
}

func TestServiceEnforcesTimeout(t *testing.T) {
	provider := &mockProvider{
		available: true,
		err:       context.DeadlineExceeded,
	}

	service := NewService(provider, time.Millisecond)

	_, err := service.Generate(context.Background(), validRequest())

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline exceeded, got %v", err)
	}
}

func TestServiceSanitizesFindingBeforeProvider(t *testing.T) {
	provider := &mockProvider{
		available: true,
		solution: RemediationSolution{
			Summary:   "Review disk usage",
			RootCause: "Disk utilization is high",
		},
	}

	service := NewService(provider, time.Second)

	request := validRequest()
	request.Finding.Source = "native"
	request.Finding.Category = "storage"
	request.Finding.Asset = "root filesystem"
	request.Finding.Severity = "high"
	request.Finding.Description = "Disk usage requires attention"
	request.Finding.Recommendation = "Review large files"
	request.Finding.Evidence = map[string]any{
		"password": "super-secret-password",
		"token":    "sensitive-token",
	}

	_, err := service.Generate(context.Background(), request)
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	got := provider.request.Finding

	if got.ID != "DISK001" ||
		got.Source != "native" ||
		got.Category != "storage" ||
		got.Asset != "root filesystem" ||
		got.Severity != "high" {
		t.Fatalf("ordinary finding fields were not preserved: %+v", got)
	}

	if got.Evidence != nil {
		t.Errorf("expected evidence to be excluded, got %v", got.Evidence)
	}

	if request.Finding.Evidence == nil {
		t.Fatal("original finding should not be modified")
	}
}

func TestServiceRedactsSecretsBeforeProvider(t *testing.T) {
	provider := &mockProvider{
		available: true,
		solution: RemediationSolution{
			Summary:   "Review configuration",
			RootCause: "Sensitive configuration was detected",
		},
	}

	service := NewService(provider, time.Second)

	request := validRequest()
	request.Finding.Message =
		"Authorization: Bearer abc123secret API_KEY=secret-value AKIAIOSFODNN7EXAMPLE"
	request.AdditionalContext =
		"password=my-secret-password and token: hidden-token"

	_, err := service.Generate(context.Background(), request)
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	finding := provider.request.Finding
	contextText := provider.request.AdditionalContext

	for _, secret := range []string{
		"abc123secret",
		"secret-value",
		"AKIAIOSFODNN7EXAMPLE",
	} {
		if strings.Contains(finding.Message, secret) {
			t.Errorf("finding message still contains secret %q", secret)
		}
	}

	for _, secret := range []string{
		"my-secret-password",
		"hidden-token",
	} {
		if strings.Contains(contextText, secret) {
			t.Errorf("additional context still contains secret %q", secret)
		}
	}

	if !strings.Contains(finding.Message, "[REDACTED]") {
		t.Error("expected redaction marker in finding message")
	}
}

func TestServiceLimitsProviderInputLength(t *testing.T) {
	provider := &mockProvider{
		available: true,
		solution: RemediationSolution{
			Summary:   "Review finding",
			RootCause: "Finding requires review",
		},
	}

	service := NewService(provider, time.Second)

	request := validRequest()
	request.Finding.Message = strings.Repeat("A", maxFindingTextBytes+1000)
	request.AdditionalContext = strings.Repeat("B", maxContextBytes+1000)

	_, err := service.Generate(context.Background(), request)
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	if len(provider.request.Finding.Message) > maxFindingTextBytes {
		t.Errorf("finding message exceeds limit: %d bytes",
			len(provider.request.Finding.Message))
	}

	if len(provider.request.AdditionalContext) > maxContextBytes {
		t.Errorf("additional context exceeds limit: %d bytes",
			len(provider.request.AdditionalContext))
	}
}
