package dashboard

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewHandlerRequiresAuthentication(t *testing.T) {
	t.Setenv("AUDITOR_HISTORY_DIR", t.TempDir())

	handler, err := NewHandler("test-dashboard-password-123")
	if err != nil {
		t.Fatalf("NewHandler returned error: %v", err)
	}

	paths := []string{
		"/",
		"/api/overview",
		"/api/metrics",
		"/api/checks",
		"/api/history",
		"/api/settings/ai-provider",
	}

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Errorf("expected 401, got %d", rec.Code)
			}

			if rec.Header().Get("WWW-Authenticate") == "" {
				t.Error("expected WWW-Authenticate header")
			}
		})
	}
}

func TestNewHandlerAcceptsValidAuthentication(t *testing.T) {
	t.Setenv("AUDITOR_HISTORY_DIR", t.TempDir())

	password := "test-dashboard-password-123"

	handler, err := NewHandler(password)
	if err != nil {
		t.Fatalf("NewHandler returned error: %v", err)
	}

	req := httptest.NewRequest(
		http.MethodGet,
		"/api/settings/ai-provider",
		nil,
	)
	req.SetBasicAuth("auditor", password)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestNewHandlerRejectsInvalidAuthentication(t *testing.T) {
	t.Setenv("AUDITOR_HISTORY_DIR", t.TempDir())

	handler, err := NewHandler("test-dashboard-password-123")
	if err != nil {
		t.Fatalf("NewHandler returned error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/overview", nil)
	req.SetBasicAuth("auditor", "incorrect-password")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestDashboardPageIncludesRequiredJavaScriptHandlers(t *testing.T) {
	t.Setenv("AUDITOR_HISTORY_DIR", t.TempDir())

	password := "test-dashboard-password-123"

	handler, err := NewHandler(password)
	if err != nil {
		t.Fatalf("NewHandler returned error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth("auditor", password)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected dashboard page status 200, got %d", rec.Code)
	}

	page := rec.Body.String()

	required := []string{
		`async function refreshAll()`,
		`async function runScan()`,
		`onclick="refreshAll()"`,
		`onclick="runScan()"`,
		`refreshAll();`,
		`setInterval(function()`,
		`refreshMetrics().catch`,
		`refreshOverview().catch`,
		`refreshHistory().catch`,
	}

	for _, fragment := range required {
		if !strings.Contains(page, fragment) {
			t.Errorf("dashboard page is missing required JavaScript or HTML: %q", fragment)
		}
	}
}

func TestDashboardPageIncludesRiskOverview(t *testing.T) {
	t.Setenv("AUDITOR_HISTORY_DIR", t.TempDir())

	handler, err := NewHandler("test-dashboard-password-123")
	if err != nil {
		t.Fatalf("NewHandler returned error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth("auditor", "test-dashboard-password-123")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	page := rec.Body.String()

	required := []string{
		"function renderRiskOverview(findings)",
		"function renderFindingDetails(finding)",
		"Risk Context",
		"Risk score:",
		"Risk band:",
		"Response guidance:",
		"Not scored",
		"Prioritize prompt review and remediation.",
		"Maximum Finding Risk",
		"Classified Findings",
		"Unclassified",
		"Highest-Risk Findings",
		"Very High",
		"Informational",
		"renderRiskOverview(findings)",
		"f.risk_score",
		"f.risk_band",
		"f.risk_priority",
		"data-finding-filter='band'",
		"data-finding-filter='priority'",
		"data-finding-filter='classification'",
		"data-finding-reset",
		"function applyFindingFilters(container)",
		"Filter by risk band",
		"Filter by priority",
		"Filter by classification",
		"Showing ",
		"Sorted by highest risk score",

		"function renderFindingExplanation(explanation)",
		"Why this matters",
		"Technical explanation",
		"Business impact",
		"Remediation rationale",
		"Impact confidence",
		"Evidence-backed",
		"Potential",
		"explanation.why_it_matters",
		"explanation.technical_explanation",
		"explanation.business_impact",
		"explanation.remediation_rationale",
		"explanation.impact_confidence",
	}

	for _, fragment := range required {
		if !strings.Contains(page, fragment) {
			t.Errorf("dashboard page is missing risk overview fragment: %q", fragment)
		}
	}
}
