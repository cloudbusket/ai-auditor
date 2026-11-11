package remediation

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
)

func openAITestStore(t *testing.T) *MemoryCredentialStore {
	t.Helper()

	store := NewMemoryCredentialStore()
	if err := store.Set("openai", "test-api-key"); err != nil {
		t.Fatal(err)
	}

	return store
}

func TestOpenAIProviderAvailable(t *testing.T) {
	provider := NewOpenAIProvider(
		openAITestStore(t),
		"test-model",
		nil,
	)

	if !provider.Available(context.Background()) {
		t.Fatal("expected provider to be available")
	}
}

func TestOpenAIProviderGenerate(t *testing.T) {
	expectedSolution := RemediationSolution{
		Summary:    "Reduce disk usage",
		RootCause:  "The root filesystem is nearly full",
		Risk:       "Applications may fail to write data",
		Confidence: "high",
		Steps: []RemediationStep{
			{Title: "Inspect large files"},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				t.Errorf("expected POST, got %s", r.Method)
			}

			if r.URL.Path != "/v1/responses" {
				t.Errorf("unexpected path: %s", r.URL.Path)
			}

			if got := r.Header.Get("Authorization"); got != "Bearer test-api-key" {
				t.Errorf("unexpected authorization header: %q", got)
			}

			if got := r.Header.Get("Content-Type"); got != "application/json" {
				t.Errorf("unexpected content type: %q", got)
			}

			var payload openAIRequest
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Errorf("decode request: %v", err)
				http.Error(w, "invalid request", http.StatusBadRequest)
				return
			}

			if payload.Store {
				t.Error("expected store=false")
			}
			if payload.Text.Format.Type != "json_schema" {
				t.Errorf(
					"expected JSON schema output format, got %q",
					payload.Text.Format.Type,
				)
			}

			if payload.Text.Format.Name != "auditor_remediation" {
				t.Errorf(
					"expected schema name auditor_remediation, got %q",
					payload.Text.Format.Name,
				)
			}

			if !payload.Text.Format.Strict {
				t.Error("expected strict JSON schema mode")
			}

			if payload.Text.Format.Schema == nil {
				t.Fatal("expected remediation JSON schema")
			}

			required, ok := payload.Text.Format.Schema["required"].([]any)
			if !ok {
				t.Fatalf("expected schema required fields, got %T",
					payload.Text.Format.Schema["required"])
			}

			expectedRequired := []string{
				"summary",
				"root_cause",
				"risk",
				"steps",
				"verification",
				"rollback",
				"assumptions",
				"confidence",
			}

			if len(required) != len(expectedRequired) {
				t.Fatalf(
					"expected %d required fields, got %d",
					len(expectedRequired),
					len(required),
				)
			}

			for i, field := range expectedRequired {
				got, ok := required[i].(string)
				if !ok {
					t.Errorf("required field at position %d is not a string", i)
					continue
				}

				if got != field {
					t.Errorf(
						"expected required field %q at position %d, got %q",
						field,
						i,
						got,
					)
				}
			}

			if payload.MaxOutputTokens != 1800 {
				t.Errorf(
					"expected max_output_tokens=1800, got %d",
					payload.MaxOutputTokens,
				)
			}

			if payload.Model != "test-model" {
				t.Errorf("unexpected model: %s", payload.Model)
			}

			if !strings.Contains(payload.Input, "DISK001") {
				t.Error("finding ID missing from input")
			}

			output, _ := json.Marshal(expectedSolution)

			response := map[string]any{
				"status": "completed",
				"output": []any{
					map[string]any{
						"type": "message",
						"role": "assistant",
						"content": []any{
							map[string]any{
								"type": "output_text",
								"text": string(output),
							},
						},
					},
				},
			}

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(response)
		},
	))
	defer server.Close()

	provider := NewOpenAIProvider(
		openAITestStore(t),
		"test-model",
		server.Client(),
	)
	provider.endpoint = server.URL + "/v1/responses"

	solution, err := provider.Generate(
		context.Background(),
		RemediationRequest{
			Finding: checks.Finding{
				ID:      "DISK001",
				Message: "Root disk usage is high",
			},
		},
	)
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	if solution.Summary != expectedSolution.Summary {
		t.Errorf("unexpected summary: %s", solution.Summary)
	}

	if solution.RootCause != expectedSolution.RootCause {
		t.Errorf("unexpected root cause: %s", solution.RootCause)
	}
}

func TestOpenAIProviderRejectsHTTPErrorWithoutLeakingBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "sensitive-provider-response", http.StatusUnauthorized)
		},
	))
	defer server.Close()

	provider := NewOpenAIProvider(
		openAITestStore(t),
		"test-model",
		server.Client(),
	)
	provider.endpoint = server.URL

	_, err := provider.Generate(
		context.Background(),
		RemediationRequest{
			Finding: checks.Finding{ID: "DISK001"},
		},
	)

	if err == nil {
		t.Fatal("expected HTTP error")
	}

	if strings.Contains(err.Error(), "sensitive-provider-response") {
		t.Fatal("provider response body leaked into error")
	}
}

func TestOpenAIProviderRejectsIncompleteResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":"completed","output":[]}`))
		},
	))
	defer server.Close()

	provider := NewOpenAIProvider(
		openAITestStore(t),
		"test-model",
		server.Client(),
	)
	provider.endpoint = server.URL

	_, err := provider.Generate(
		context.Background(),
		RemediationRequest{
			Finding: checks.Finding{ID: "DISK001"},
		},
	)

	if !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("expected ErrInvalidResponse, got %v", err)
	}
}
func TestOpenAIProviderRejectsOversizedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)

			_, _ = w.Write([]byte(`{"status":"completed","output":[]}`))
			_, _ = w.Write(make([]byte, maxOpenAIResponseBytes))
		},
	))
	defer server.Close()

	provider := NewOpenAIProvider(
		openAITestStore(t),
		"test-model",
		server.Client(),
	)
	provider.endpoint = server.URL

	_, err := provider.Generate(
		context.Background(),
		RemediationRequest{
			Finding: checks.Finding{ID: "DISK001"},
		},
	)

	if !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("expected ErrInvalidResponse, got %v", err)
	}
}

func TestOpenAIProviderHonorsRequestCancellation(t *testing.T) {
	requestStarted := make(chan struct{})
	releaseHandler := make(chan struct{})

	server := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			close(requestStarted)

			select {
			case <-releaseHandler:
			case <-r.Context().Done():
			}
		},
	))

	defer func() {
		close(releaseHandler)
		server.Close()
	}()

	provider := NewOpenAIProvider(
		openAITestStore(t),
		"test-model",
		server.Client(),
	)
	provider.endpoint = server.URL

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)

	go func() {
		_, err := provider.Generate(
			ctx,
			RemediationRequest{
				Finding: checks.Finding{ID: "DISK001"},
			},
		)
		done <- err
	}()

	select {
	case <-requestStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("HTTP request did not reach mock server")
	}

	cancel()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected request cancellation error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("provider did not stop after request cancellation")
	}
}
func TestOpenAIProviderHandlesRefusalAndIncompleteResponses(t *testing.T) {
	tests := []struct {
		name         string
		response     string
		expectedText string
	}{
		{
			name: "refusal",
			response: `{
				"status": "completed",
				"output": [{
					"type": "message",
					"role": "assistant",
					"content": [{
						"type": "refusal",
						"refusal": "Sensitive refusal details"
					}]
				}]
			}`,
			expectedText: "declined the remediation request",
		},
		{
			name: "maximum output tokens",
			response: `{
				"status": "incomplete",
				"incomplete_details": {
					"reason": "max_output_tokens"
				},
				"output": []
			}`,
			expectedText: "output-token limit",
		},
		{
			name: "other incomplete response",
			response: `{
				"status": "incomplete",
				"incomplete_details": {
					"reason": "content_filter"
				},
				"output": []
			}`,
			expectedText: "incomplete response",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(tt.response))
				},
			))
			defer server.Close()

			provider := NewOpenAIProvider(
				openAITestStore(t),
				"test-model",
				server.Client(),
			)
			provider.endpoint = server.URL

			_, err := provider.Generate(
				context.Background(),
				RemediationRequest{
					Finding: checks.Finding{ID: "DISK001"},
				},
			)

			if err == nil {
				t.Fatal("expected an error")
			}

			if !strings.Contains(err.Error(), tt.expectedText) {
				t.Errorf(
					"expected error containing %q, got %q",
					tt.expectedText,
					err.Error(),
				)
			}

			if strings.Contains(err.Error(), "Sensitive refusal details") {
				t.Error("refusal details leaked into error")
			}
		})
	}
}
