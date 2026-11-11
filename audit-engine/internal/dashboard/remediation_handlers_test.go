package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cloudbusket/ai-auditor/audit-engine/internal/checks"
	"github.com/cloudbusket/ai-auditor/audit-engine/internal/remediation"
)

type dashboardTestProvider struct {
	available bool
	solution  remediation.RemediationSolution
	err       error
	called    bool
}

func (p *dashboardTestProvider) Name() string {
	return "test-provider"
}

func (p *dashboardTestProvider) Available(context.Context) bool {
	return p.available
}

func (p *dashboardTestProvider) Generate(
	ctx context.Context,
	request remediation.RemediationRequest,
) (remediation.RemediationSolution, error) {
	p.called = true

	if p.err != nil {
		return remediation.RemediationSolution{}, p.err
	}

	return p.solution, nil
}

func newDashboardTestHistory(t *testing.T) (*HistoryStore, string) {
	t.Helper()

	history, err := NewHistoryStore(t.TempDir())
	if err != nil {
		t.Fatalf("create history store: %v", err)
	}

	record, err := history.Save(checks.Report{
		OverallStatus: checks.StatusCritical,
		Findings: []checks.Finding{
			{
				ID:             "DISK001",
				Source:         "native",
				Category:       "storage",
				Asset:          "root filesystem",
				Status:         checks.StatusCritical,
				Severity:       "high",
				Message:        "Root filesystem usage is high",
				Recommendation: "Investigate disk usage",
			},
		},
	})
	if err != nil {
		t.Fatalf("save test history: %v", err)
	}

	return history, record.ID
}

func newDashboardTestService(
	provider *dashboardTestProvider,
) *remediation.Service {
	return remediation.NewService(provider, time.Second)
}

func TestProviderSettingsGET(t *testing.T) {
	store := remediation.NewMemoryCredentialStore()

	handler := providerSettingsHandler(store)

	request := httptest.NewRequest(http.MethodGet, "/api/settings/ai-provider", nil)
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", recorder.Code, recorder.Body.String())
	}

	var response map[string]interface{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if response["configured"] != false {
		t.Errorf("expected configured=false, got %v", response["configured"])
	}

	if response["storage"] != "memory" {
		t.Errorf("expected memory storage, got %v", response["storage"])
	}
}

func TestProviderSettingsPOSTAndDELETE(t *testing.T) {
	store := remediation.NewMemoryCredentialStore()
	handler := providerSettingsHandler(store)

	post := httptest.NewRequest(
		http.MethodPost,
		"/api/settings/ai-provider",
		strings.NewReader(`{"api_key":"test-api-key"}`),
	)
	post.Header.Set("Content-Type", "application/json")
	post.Header.Set("Origin", "http://example.test")
	post.Host = "example.test"

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, post)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected POST 200, got %d: %s", recorder.Code, recorder.Body.String())
	}

	if !store.Has("openai") {
		t.Fatal("expected OpenAI key to be stored")
	}

	deleteRequest := httptest.NewRequest(
		http.MethodDelete,
		"/api/settings/ai-provider",
		nil,
	)
	deleteRequest.Header.Set("Origin", "http://example.test")
	deleteRequest.Host = "example.test"

	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, deleteRequest)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected DELETE 200, got %d: %s", recorder.Code, recorder.Body.String())
	}

	if store.Has("openai") {
		t.Fatal("expected OpenAI key to be deleted")
	}
}

func TestProviderSettingsRejectsCrossOrigin(t *testing.T) {
	store := remediation.NewMemoryCredentialStore()
	handler := providerSettingsHandler(store)

	request := httptest.NewRequest(
		http.MethodPost,
		"/api/settings/ai-provider",
		strings.NewReader(`{"api_key":"test-api-key"}`),
	)
	request.Header.Set("Origin", "https://attacker.example")
	request.Host = "dashboard.example"

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", recorder.Code)
	}

	if store.Has("openai") {
		t.Fatal("cross-origin request must not store the API key")
	}
}

func TestProviderSettingsRejectsInvalidJSON(t *testing.T) {
	store := remediation.NewMemoryCredentialStore()
	handler := providerSettingsHandler(store)

	tests := []struct {
		name string
		body string
	}{
		{
			name: "malformed JSON",
			body: `{"api_key":`,
		},
		{
			name: "unknown field",
			body: `{"api_key":"test","unexpected":"value"}`,
		},
		{
			name: "multiple JSON values",
			body: `{"api_key":"test"} {"api_key":"another"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := httptest.NewRequest(
				http.MethodPost,
				"/api/settings/ai-provider",
				strings.NewReader(tt.body),
			)
			request.Header.Set("Origin", "http://example.test")
			request.Host = "example.test"

			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)

			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d", recorder.Code)
			}

			if store.Has("openai") {
				t.Fatal("invalid request must not store an API key")
			}
		})
	}
}

func TestFindingRemediationRejectsUnavailableProvider(t *testing.T) {
	history, scanID := newDashboardTestHistory(t)

	provider := &dashboardTestProvider{available: false}
	service := newDashboardTestService(provider)

	handler := findingRemediationHandler(history, service)

	request := httptest.NewRequest(
		http.MethodPost,
		"/api/history/"+scanID+"/findings/DISK001/remediation",
		strings.NewReader(`{}`),
	)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", recorder.Code, recorder.Body.String())
	}

	if provider.called {
		t.Fatal("unavailable provider must not be called")
	}
}

func TestFindingRemediationRejectsCrossOrigin(t *testing.T) {
	history, scanID := newDashboardTestHistory(t)

	provider := &dashboardTestProvider{available: true}
	service := newDashboardTestService(provider)

	handler := findingRemediationHandler(history, service)

	request := httptest.NewRequest(
		http.MethodPost,
		"/api/history/"+scanID+"/findings/DISK001/remediation",
		strings.NewReader(`{}`),
	)
	request.Header.Set("Origin", "https://attacker.example")
	request.Host = "dashboard.example"

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", recorder.Code)
	}

	if provider.called {
		t.Fatal("cross-origin request must not invoke provider")
	}
}

func TestFindingRemediationRejectsMissingScanAndFinding(t *testing.T) {
	history, scanID := newDashboardTestHistory(t)

	provider := &dashboardTestProvider{available: true}
	service := newDashboardTestService(provider)

	handler := findingRemediationHandler(history, service)

	tests := []struct {
		name string
		path string
	}{
		{
			name: "missing scan",
			path: "/api/history/0000000000000000/findings/DISK001/remediation",
		},
		{
			name: "missing finding",
			path: "/api/history/" + scanID + "/findings/UNKNOWN/remediation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, tt.path, strings.NewReader(`{}`))
			recorder := httptest.NewRecorder()

			handler.ServeHTTP(recorder, request)

			if recorder.Code != http.StatusNotFound {
				t.Fatalf("expected 404, got %d", recorder.Code)
			}
		})
	}

	if provider.called {
		t.Fatal("missing scan or finding must not invoke provider")
	}
}

func TestFindingRemediationRejectsInvalidContext(t *testing.T) {
	history, scanID := newDashboardTestHistory(t)

	provider := &dashboardTestProvider{available: true}
	service := newDashboardTestService(provider)

	handler := findingRemediationHandler(history, service)

	tests := []struct {
		name string
		body string
	}{
		{
			name: "unknown field",
			body: `{"unexpected":"value"}`,
		},
		{
			name: "multiple JSON values",
			body: `{} {}`,
		},
		{
			name: "context too long",
			body: `{"additional_context":"` +
				strings.Repeat("A", 4001) + `"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := httptest.NewRequest(
				http.MethodPost,
				"/api/history/"+scanID+"/findings/DISK001/remediation",
				strings.NewReader(tt.body),
			)

			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)

			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d: %s", recorder.Code, recorder.Body.String())
			}
		})
	}

	if provider.called {
		t.Fatal("invalid context must not invoke provider")
	}
}

func TestFindingRemediationGeneratesAdvisorySolution(t *testing.T) {
	history, scanID := newDashboardTestHistory(t)

	provider := &dashboardTestProvider{
		available: true,
		solution: remediation.RemediationSolution{
			Summary:    "Review filesystem usage",
			RootCause:  "The root filesystem is nearly full",
			Risk:       "Applications may fail to write data",
			Confidence: "high",
			Steps: []remediation.RemediationStep{
				{
					Title:       "Inspect disk usage",
					Description: "Identify large directories before taking action.",
					Command:     "df -h",
				},
			},
			Verification: []string{"Check filesystem usage again"},
			Rollback:     []string{"No changes have been made"},
		},
	}

	service := newDashboardTestService(provider)
	handler := findingRemediationHandler(history, service)

	request := httptest.NewRequest(
		http.MethodPost,
		"/api/history/"+scanID+"/findings/DISK001/remediation",
		strings.NewReader(`{"additional_context":"Production root filesystem"}`),
	)
	request.Header.Set("Content-Type", "application/json")

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", recorder.Code, recorder.Body.String())
	}

	if !provider.called {
		t.Fatal("expected provider to be called")
	}

	var solution remediation.RemediationSolution
	if err := json.Unmarshal(recorder.Body.Bytes(), &solution); err != nil {
		t.Fatalf("decode remediation response: %v", err)
	}

	if !solution.AdvisoryOnly {
		t.Error("expected advisory-only response")
	}

	if solution.Provider != "test-provider" {
		t.Errorf("unexpected provider: %q", solution.Provider)
	}

	if solution.Summary != "Review filesystem usage" {
		t.Errorf("unexpected summary: %q", solution.Summary)
	}

	if solution.GeneratedAt.IsZero() {
		t.Error("expected generated_at timestamp")
	}
}

func TestFindingRemediationRejectsWrongMethod(t *testing.T) {
	history, scanID := newDashboardTestHistory(t)

	provider := &dashboardTestProvider{available: true}
	service := newDashboardTestService(provider)

	handler := findingRemediationHandler(history, service)

	request := httptest.NewRequest(
		http.MethodGet,
		"/api/history/"+scanID+"/findings/DISK001/remediation",
		nil,
	)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", recorder.Code)
	}

	if got := recorder.Header().Get("Allow"); got != http.MethodPost {
		t.Errorf("expected Allow: POST, got %q", got)
	}
}

func TestFindingRemediationDoesNotExposeProviderError(t *testing.T) {
	history, scanID := newDashboardTestHistory(t)

	provider := &dashboardTestProvider{
		available: true,
		err:       errors.New("private-provider-error-detail"),
	}
	service := newDashboardTestService(provider)

	handler := findingRemediationHandler(history, service)

	request := httptest.NewRequest(
		http.MethodPost,
		"/api/history/"+scanID+"/findings/DISK001/remediation",
		strings.NewReader(`{}`),
	)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", recorder.Code)
	}

	if strings.Contains(recorder.Body.String(), "private-provider-error-detail") {
		t.Fatal("provider error details leaked to HTTP response")
	}
}
