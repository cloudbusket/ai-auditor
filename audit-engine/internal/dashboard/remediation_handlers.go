package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/cloudbusket/ai-auditor/audit-engine/internal/checks"
	"github.com/cloudbusket/ai-auditor/audit-engine/internal/remediation"
)

type providerKeyRequest struct {
	APIKey string `json:"api_key"`
}

type remediationContextRequest struct {
	AdditionalContext string `json:"additional_context,omitempty"`
}

func decodeJSONBody(
	w http.ResponseWriter,
	r *http.Request,
	maxBytes int64,
	destination any,
) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	defer r.Body.Close()

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(destination); err != nil {
		return err
	}

	// Reject multiple JSON values in one request.
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}

	return nil
}

func providerSettingsHandler(
	credentials remediation.CredentialStore,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"provider":   "openai",
				"configured": credentials.Has("openai"),
				"storage":    "memory",
			})

		case http.MethodPost:
			if !sameOriginRequest(r) {
				http.Error(w, "Cross-origin request rejected", http.StatusForbidden)
				return
			}

			var request providerKeyRequest

			if err := decodeJSONBody(w, r, 8*1024, &request); err != nil {
				http.Error(w, "Invalid request body", http.StatusBadRequest)
				return
			}

			if err := credentials.Set("openai", request.APIKey); err != nil {
				http.Error(w, "Invalid API key", http.StatusBadRequest)
				return
			}

			writeJSON(w, http.StatusOK, map[string]interface{}{
				"provider":   "openai",
				"configured": true,
				"storage":    "memory",
			})

		case http.MethodDelete:
			if !sameOriginRequest(r) {
				http.Error(w, "Cross-origin request rejected", http.StatusForbidden)
				return
			}

			if err := credentials.Delete("openai"); err != nil {
				http.Error(w, "Unable to remove provider key", http.StatusInternalServerError)
				return
			}

			writeJSON(w, http.StatusOK, map[string]bool{
				"configured": false,
			})

		default:
			w.Header().Set("Allow", "GET, POST, DELETE")
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

func findingRemediationHandler(
	history *HistoryStore,
	service *remediation.Service,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if !sameOriginRequest(r) {
			http.Error(w, "Cross-origin request rejected", http.StatusForbidden)
			return
		}

		path := strings.TrimPrefix(r.URL.Path, "/api/history/")
		parts := strings.Split(path, "/")

		if len(parts) != 4 ||
			parts[1] != "findings" ||
			parts[3] != "remediation" {
			http.NotFound(w, r)
			return
		}

		scanID := parts[0]
		findingID := parts[2]

		record, err := history.Get(scanID)
		if err != nil {
			http.NotFound(w, r)
			return
		}

		var finding *checks.Finding

		for i := range record.Report.Findings {
			if record.Report.Findings[i].ID == findingID {
				finding = &record.Report.Findings[i]
				break
			}
		}

		if finding == nil {
			http.NotFound(w, r)
			return
		}

		var request remediationContextRequest

		if err := decodeJSONBody(w, r, 8*1024, &request); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		if len(request.AdditionalContext) > 4000 {
			http.Error(w, "Additional context is too long", http.StatusBadRequest)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 75*time.Second)
		defer cancel()

		solution, err := service.Generate(ctx, remediation.RemediationRequest{
			Finding:           *finding,
			AdditionalContext: request.AdditionalContext,
		})
		if err != nil {
			if errors.Is(err, remediation.ErrProviderUnavailable) {
				http.Error(w, "OpenAI provider is not configured", http.StatusServiceUnavailable)
				return
			}

			if errors.Is(err, context.DeadlineExceeded) {
				http.Error(w, "Remediation request timed out", http.StatusGatewayTimeout)
				return
			}

			http.Error(w, "Unable to generate remediation", http.StatusBadGateway)
			return
		}

		writeJSON(w, http.StatusOK, solution)
	}
}
