package dashboard

import (
	"net/http"
	"net/http/httptest"
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
