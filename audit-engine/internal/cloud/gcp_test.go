package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

func newTestGCPCollector(server *httptest.Server) *GCPCollector {
	return &GCPCollector{
		HTTPClient:         server.Client(),
		TokenSource:        oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test-token"}),
		ResourceManagerURL: server.URL + "/v3",
		ServiceUsageURL:    server.URL + "/v1",
		ComputeURL:         server.URL + "/compute/v1",
	}
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeGCPError(w http.ResponseWriter, status int, reason, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{
			"code":    status,
			"message": message,
			"status":  http.StatusText(status),
			"errors": []map[string]string{
				{"reason": reason},
			},
		},
	})
}

func serveGCPProject(w http.ResponseWriter) {
	writeJSON(w, http.StatusOK, map[string]any{
		"name":       "projects/123456789",
		"projectId":  "test-project",
		"state":      "ACTIVE",
		"parent":     "organizations/987654321",
		"createTime": "2026-01-01T00:00:00Z",
		"labels": map[string]string{
			"environment": "test",
		},
	})
}

func TestGCPDiscoverSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("unexpected authorization header: %q", r.Header.Get("Authorization"))
		}

		switch {
		case r.URL.Path == "/v3/projects/test-project":
			serveGCPProject(w)

		case r.URL.Path == "/v1/projects/test-project/services":
			if r.URL.Query().Get("filter") != "state:ENABLED" {
				t.Errorf("unexpected service filter: %q", r.URL.Query().Get("filter"))
			}

			writeJSON(w, http.StatusOK, gcpServicesResponse{
				Services: []gcpServiceResponse{
					{Name: "compute.googleapis.com", State: "ENABLED"},
					{Name: "storage.googleapis.com", State: "ENABLED"},
				},
			})

		case r.URL.Path == "/compute/v1/projects/test-project/aggregated/instances":
			writeJSON(w, http.StatusOK, map[string]any{
				"items": map[string]any{
					"zones/us-west1-b": map[string]any{
						"instances": []map[string]any{
							{
								"id":          "111",
								"name":        "test-vm",
								"machineType": "zones/us-west1-b/machineTypes/e2-medium",
								"zone":        "zones/us-west1-b",
								"status":      "RUNNING",
								"labels":      map[string]string{"environment": "test"},
								"networkInterfaces": []map[string]any{
									{
										"name":      "nic0",
										"networkIP": "10.0.0.2",
										"accessConfigs": []map[string]any{
											{"natIP": "203.0.113.10"},
										},
									},
								},
							},
						},
					},
				},
			})

		case r.URL.Path == "/compute/v1/projects/test-project/aggregated/disks":
			writeJSON(w, http.StatusOK, map[string]any{
				"items": map[string]any{
					"zones/us-west1-b": map[string]any{
						"disks": []map[string]any{
							{
								"id":     "222",
								"name":   "test-disk",
								"zone":   "zones/us-west1-b",
								"sizeGb": "50",
								"type":   "zones/us-west1-b/diskTypes/pd-balanced",
								"status": "READY",
								"users":  []string{},
							},
						},
					},
				},
			})

		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	collector := newTestGCPCollector(server)

	inv, err := collector.Discover(context.Background(), Config{
		ProjectID: "test-project",
	})
	if err != nil {
		t.Fatalf("Discover returned error: %v", err)
	}

	if inv.Provider != ProviderGCP {
		t.Errorf("expected provider %q, got %q", ProviderGCP, inv.Provider)
	}

	if inv.ProjectID != "test-project" {
		t.Errorf("expected project ID test-project, got %q", inv.ProjectID)
	}

	if inv.AccountID != "123456789" {
		t.Errorf("expected project number 123456789, got %q", inv.AccountID)
	}

	if len(inv.Resources) != 5 {
		t.Fatalf("expected 5 resources, got %d", len(inv.Resources))
	}

	if inv.Resources[0].Type != "gcp.project" {
		t.Errorf("expected first resource to be gcp.project, got %q", inv.Resources[0].Type)
	}

	if inv.Resources[1].Type != "gcp.service" {
		t.Errorf("expected service resource, got %q", inv.Resources[1].Type)
	}

	if len(inv.Coverage) != 4 {
		t.Fatalf("expected 4 coverage records, got %d", len(inv.Coverage))
	}

	for _, coverage := range inv.Coverage {
		if coverage.Status != CoverageCompleted {
			t.Errorf("expected completed coverage for %s, got %s",
				coverage.Category, coverage.Status)
		}
	}
}

func TestGCPDiscoverPermissionDenied(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v3/projects/test-project" {
			serveGCPProject(w)
			return
		}

		if r.URL.Path == "/v1/projects/test-project/services" {
			writeGCPError(w, http.StatusForbidden, "forbidden", "permission denied")
			return
		}

		http.NotFound(w, r)
	}))
	defer server.Close()

	collector := newTestGCPCollector(server)

	inv, err := collector.Discover(context.Background(), Config{
		ProjectID: "test-project",
	})
	if err != nil {
		t.Fatalf("expected partial inventory without fatal error, got %v", err)
	}

	if len(inv.Resources) != 1 {
		t.Fatalf("expected project metadata to be retained, got %d resources", len(inv.Resources))
	}

	coverage := inv.Coverage[1]
	if coverage.Status != CoveragePermissionDenied {
		t.Errorf("expected permission_denied, got %s", coverage.Status)
	}

	if coverage.ResourceCount != 0 {
		t.Errorf("expected zero services, got %d", coverage.ResourceCount)
	}
}

func TestGCPDiscoverDisabledAPI(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v3/projects/test-project" {
			serveGCPProject(w)
			return
		}

		if r.URL.Path == "/v1/projects/test-project/services" {
			writeGCPError(w, http.StatusForbidden, "SERVICE_DISABLED", "service usage API is disabled")
			return
		}

		http.NotFound(w, r)
	}))
	defer server.Close()

	collector := newTestGCPCollector(server)

	inv, err := collector.Discover(context.Background(), Config{
		ProjectID: "test-project",
	})
	if err != nil {
		t.Fatalf("expected partial inventory without fatal error, got %v", err)
	}

	coverage := inv.Coverage[1]
	if coverage.Status != CoverageAPIDisabled {
		t.Errorf("expected api_disabled, got %s", coverage.Status)
	}
}

func TestGCPDiscoverPartialPagination(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v3/projects/test-project":
			serveGCPProject(w)

		case r.URL.Path == "/v1/projects/test-project/services":
			if r.URL.Query().Get("pageToken") == "" {
				writeJSON(w, http.StatusOK, gcpServicesResponse{
					Services: []gcpServiceResponse{
						{Name: "compute.googleapis.com", State: "ENABLED"},
					},
					NextPageToken: "next-page",
				})
				return
			}

			writeGCPError(w, http.StatusForbidden, "forbidden", "second page denied")

		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	collector := newTestGCPCollector(server)

	inv, err := collector.Discover(context.Background(), Config{
		ProjectID: "test-project",
	})
	if err != nil {
		t.Fatalf("expected partial inventory without fatal error, got %v", err)
	}

	if len(inv.Resources) != 2 {
		t.Fatalf("expected project and one service, got %d resources", len(inv.Resources))
	}

	coverage := inv.Coverage[1]

	if coverage.Status != CoveragePartial {
		t.Errorf("expected partial coverage, got %s", coverage.Status)
	}

	if coverage.ResourceCount != 1 {
		t.Errorf("expected one collected service, got %d", coverage.ResourceCount)
	}

	if !strings.Contains(coverage.Message, "second page denied") {
		t.Errorf("expected pagination error message, got %q", coverage.Message)
	}
}

func TestGCPDiscoverRejectsMissingProjectID(t *testing.T) {
	collector := &GCPCollector{
		TokenSource: oauth2.StaticTokenSource(&oauth2.Token{
			AccessToken: "test-token",
		}),
	}

	_, err := collector.Discover(context.Background(), Config{})
	if err == nil {
		t.Fatal("expected error for missing project ID")
	}
}

func TestGCPDiscoverRejectsMissingCredentials(t *testing.T) {
	collector := &GCPCollector{}

	_, err := collector.Discover(context.Background(), Config{
		ProjectID: "test-project",
	})
	if err == nil {
		t.Fatal("expected error for missing credentials")
	}
}

func TestParseGCPProjectNumber(t *testing.T) {
	got, err := parseGCPProjectNumber("projects/123456789")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got != "123456789" {
		t.Errorf("expected 123456789, got %q", got)
	}

	invalidNames := []string{
		"",
		"test-project",
		"projects/",
		"projects/not-a-number",
	}

	for _, name := range invalidNames {
		t.Run(fmt.Sprintf("%q", name), func(t *testing.T) {
			if _, err := parseGCPProjectNumber(name); err == nil {
				t.Errorf("expected error for project resource name %q", name)
			}
		})
	}
}
