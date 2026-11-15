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
		HTTPClient:            server.Client(),
		TokenSource:           oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test-token"}),
		ResourceManagerURL:    server.URL + "/v3",
		ServiceUsageURL:       server.URL + "/v1",
		ComputeURL:            server.URL + "/compute/v1",
		IAMResourceManagerURL: server.URL + "/v3",
		IAMURL:                server.URL + "/iam/v1",
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
		if r.Method == http.MethodPost &&
			r.URL.Path == "/v3/projects/test-project:getIamPolicy" {
			if r.Header.Get("Authorization") != "Bearer test-token" {
				t.Errorf("unexpected IAM authorization header: %q",
					r.Header.Get("Authorization"))
			}

			var request gcpIAMPolicyRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Errorf("decode IAM policy request: %v", err)
			}
			if request.Options.RequestedPolicyVersion != 3 {
				t.Errorf("expected IAM policy version 3, got %d",
					request.Options.RequestedPolicyVersion)
			}

			writeJSON(w, http.StatusOK, gcpIAMPolicyResponse{
				Version: 3,
			})
			return
		}

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
					{Name: "iam.googleapis.com", State: "ENABLED"},
				},
			})

		case r.URL.Path == "/iam/v1/projects/test-project/serviceAccounts":
			if r.URL.Query().Get("pageSize") != "100" {
				t.Errorf("unexpected service account page size: %q",
					r.URL.Query().Get("pageSize"))
			}

			writeJSON(w, http.StatusOK, map[string]any{
				"accounts": []map[string]any{
					{
						"name":           "projects/test-project/serviceAccounts/test-sa@test-project.iam.gserviceaccount.com",
						"projectId":      "test-project",
						"uniqueId":       "123456789",
						"email":          "test-sa@test-project.iam.gserviceaccount.com",
						"displayName":    "Test service account",
						"oauth2ClientId": "12345",
						"disabled":       false,
					},
				},
			})

		case r.URL.Path == "/iam/v1/projects/test-project/serviceAccounts/test-sa@test-project.iam.gserviceaccount.com/keys":
			if r.URL.Query().Get("keyTypes") != "USER_MANAGED" {
				t.Errorf("expected USER_MANAGED keys, got %q",
					r.URL.Query().Get("keyTypes"))
			}
			if r.URL.Query().Get("pageSize") != "100" {
				t.Errorf("expected key page size 100, got %q",
					r.URL.Query().Get("pageSize"))
			}
			writeJSON(w, http.StatusOK, gcpServiceAccountKeysResponse{
				Keys: []gcpServiceAccountKey{},
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

	if len(inv.Resources) != 7 {
		t.Fatalf("expected 7 resources, got %d", len(inv.Resources))
	}

	if inv.Resources[0].Type != "gcp.project" {
		t.Errorf("expected first resource to be gcp.project, got %q", inv.Resources[0].Type)
	}

	if inv.Resources[1].Type != "gcp.service" {
		t.Errorf("expected service resource, got %q", inv.Resources[1].Type)
	}

	var serviceAccount *Resource

	for i := range inv.Resources {
		if inv.Resources[i].Type == "gcp.iam.service_account" {
			serviceAccount = &inv.Resources[i]
			break
		}
	}

	if serviceAccount == nil {
		t.Fatal("expected a gcp.iam.service_account resource")
	}

	if serviceAccount.Name != "test-sa@test-project.iam.gserviceaccount.com" {
		t.Errorf("unexpected service account name: %q", serviceAccount.Name)
	}

	expectedProperties := map[string]any{
		"email":            "test-sa@test-project.iam.gserviceaccount.com",
		"unique_id":        "123456789",
		"display_name":     "Test service account",
		"disabled":         false,
		"oauth2_client_id": "12345",
	}

	for key, want := range expectedProperties {
		if got := serviceAccount.Properties[key]; got != want {
			t.Errorf("service account property %q: expected %v, got %v",
				key, want, got)
		}
	}

	if len(inv.Coverage) != 7 {
		t.Fatalf("expected 7 coverage records, got %d", len(inv.Coverage))
	}

	keyCoverageFound := false

	for _, coverage := range inv.Coverage {
		if coverage.Category == "iam_service_account_keys" {
			keyCoverageFound = true
		}

		if coverage.Status != CoverageCompleted {
			t.Errorf("expected completed coverage for %s, got %s",
				coverage.Category, coverage.Status)
		}
	}
	if !keyCoverageFound {
		t.Error("expected iam_service_account_keys coverage")
	}

}

func TestGCPDiscoverPermissionDenied(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost &&
			r.URL.Path == "/v3/projects/test-project:getIamPolicy" {
			if r.Header.Get("Authorization") != "Bearer test-token" {
				t.Errorf("unexpected IAM authorization header: %q",
					r.Header.Get("Authorization"))
			}

			var request gcpIAMPolicyRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Errorf("decode IAM policy request: %v", err)
			}
			if request.Options.RequestedPolicyVersion != 3 {
				t.Errorf("expected IAM policy version 3, got %d",
					request.Options.RequestedPolicyVersion)
			}

			writeJSON(w, http.StatusOK, gcpIAMPolicyResponse{
				Version: 3,
			})
			return
		}

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

	var coverage Coverage
	for _, item := range inv.Coverage {
		if item.Category == "enabled_services" {
			coverage = item
			break
		}
	}
	if coverage.Category == "" {
		t.Fatal("enabled_services coverage record not found")
	}
	if coverage.Status != CoveragePermissionDenied {
		t.Errorf("expected permission_denied, got %s", coverage.Status)
	}

	if coverage.ResourceCount != 0 {
		t.Errorf("expected zero services, got %d", coverage.ResourceCount)
	}
}

func TestGCPDiscoverDisabledAPI(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost &&
			r.URL.Path == "/v3/projects/test-project:getIamPolicy" {
			if r.Header.Get("Authorization") != "Bearer test-token" {
				t.Errorf("unexpected IAM authorization header: %q",
					r.Header.Get("Authorization"))
			}

			var request gcpIAMPolicyRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Errorf("decode IAM policy request: %v", err)
			}
			if request.Options.RequestedPolicyVersion != 3 {
				t.Errorf("expected IAM policy version 3, got %d",
					request.Options.RequestedPolicyVersion)
			}

			writeJSON(w, http.StatusOK, gcpIAMPolicyResponse{
				Version: 3,
			})
			return
		}

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

	var coverage Coverage
	for _, item := range inv.Coverage {
		if item.Category == "enabled_services" {
			coverage = item
			break
		}
	}
	if coverage.Category == "" {
		t.Fatal("enabled_services coverage record not found")
	}
	if coverage.Status != CoverageAPIDisabled {
		t.Errorf("expected api_disabled, got %s", coverage.Status)
	}
}

func TestGCPDiscoverPartialPagination(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost &&
			r.URL.Path == "/v3/projects/test-project:getIamPolicy" {
			if r.Header.Get("Authorization") != "Bearer test-token" {
				t.Errorf("unexpected IAM authorization header: %q",
					r.Header.Get("Authorization"))
			}

			var request gcpIAMPolicyRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Errorf("decode IAM policy request: %v", err)
			}
			if request.Options.RequestedPolicyVersion != 3 {
				t.Errorf("expected IAM policy version 3, got %d",
					request.Options.RequestedPolicyVersion)
			}

			writeJSON(w, http.StatusOK, gcpIAMPolicyResponse{
				Version: 3,
			})
			return
		}

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

	var coverage Coverage
	for _, item := range inv.Coverage {
		if item.Category == "enabled_services" {
			coverage = item
			break
		}
	}
	if coverage.Category == "" {
		t.Fatal("enabled_services coverage record not found")
	}

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
func TestGCPCollectServiceAccountsPagination(t *testing.T) {
	pageRequests := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("unexpected authorization header: %q", r.Header.Get("Authorization"))
		}

		if r.URL.Path != "/iam/v1/projects/test-project/serviceAccounts" {
			http.NotFound(w, r)
			return
		}

		if r.URL.Query().Get("pageSize") != "100" {
			t.Errorf("expected pageSize 100, got %q", r.URL.Query().Get("pageSize"))
		}

		pageRequests++

		switch r.URL.Query().Get("pageToken") {
		case "":
			writeJSON(w, http.StatusOK, map[string]any{
				"accounts": []map[string]any{
					{
						"name":        "projects/test-project/serviceAccounts/first@test-project.iam.gserviceaccount.com",
						"email":       "first@test-project.iam.gserviceaccount.com",
						"uniqueId":    "111",
						"displayName": "First account",
					},
				},
				"nextPageToken": "page-2",
			})

		case "page-2":
			writeJSON(w, http.StatusOK, map[string]any{
				"accounts": []map[string]any{
					{
						"name":        "projects/test-project/serviceAccounts/second@test-project.iam.gserviceaccount.com",
						"email":       "second@test-project.iam.gserviceaccount.com",
						"uniqueId":    "222",
						"displayName": "Second account",
						"disabled":    true,
					},
				},
			})

		default:
			t.Errorf("unexpected page token: %q", r.URL.Query().Get("pageToken"))
			http.Error(w, "unexpected page token", http.StatusBadRequest)
		}
	}))
	defer server.Close()

	collector := newTestGCPCollector(server)

	inv := Inventory{
		Provider:  ProviderGCP,
		ProjectID: "test-project",
	}

	count, err := collector.collectServiceAccounts(
		context.Background(),
		server.Client(),
		server.URL+"/iam/v1",
		"test-project",
		&inv,
	)
	if err != nil {
		t.Fatalf("service account collection failed: %v", err)
	}

	if count != 2 {
		t.Fatalf("expected 2 service accounts, got %d", count)
	}

	if pageRequests != 2 {
		t.Fatalf("expected 2 page requests, got %d", pageRequests)
	}

	if len(inv.Resources) != 2 {
		t.Fatalf("expected 2 resources, got %d", len(inv.Resources))
	}

	if inv.Resources[0].Properties["email"] != "first@test-project.iam.gserviceaccount.com" {
		t.Errorf("unexpected first account: %v", inv.Resources[0].Properties["email"])
	}

	if inv.Resources[1].Properties["email"] != "second@test-project.iam.gserviceaccount.com" {
		t.Errorf("unexpected second account: %v", inv.Resources[1].Properties["email"])
	}

	if inv.Resources[1].Properties["disabled"] != true {
		t.Errorf("expected second service account to be disabled")
	}
}

func TestGCPCollectServiceAccountsPartialPagination(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("pageToken") == "" {
			writeJSON(w, http.StatusOK, map[string]any{
				"accounts": []map[string]any{
					{
						"name":  "projects/test-project/serviceAccounts/first@test-project.iam.gserviceaccount.com",
						"email": "first@test-project.iam.gserviceaccount.com",
					},
				},
				"nextPageToken": "page-2",
			})
			return
		}

		writeGCPError(w, http.StatusForbidden, "forbidden", "second service account page denied")
	}))
	defer server.Close()

	collector := newTestGCPCollector(server)

	inv := Inventory{
		Provider:  ProviderGCP,
		ProjectID: "test-project",
	}

	count, err := collector.collectServiceAccounts(
		context.Background(),
		server.Client(),
		server.URL+"/iam/v1",
		"test-project",
		&inv,
	)

	if err == nil {
		t.Fatal("expected permission error on second page")
	}

	if count != 1 {
		t.Errorf("expected 1 collected service account, got %d", count)
	}

	if len(inv.Resources) != 1 {
		t.Errorf("expected first-page resource to be preserved, got %d", len(inv.Resources))
	}

	if !strings.Contains(err.Error(), "second service account page denied") {
		t.Errorf("unexpected error message: %v", err)
	}

	if classifyGCPError(err) != CoveragePermissionDenied {
		t.Errorf("expected permission_denied classification, got %s",
			classifyGCPError(err))
	}
}

func TestGCPCollectServiceAccountsPermissionDenied(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeGCPError(w, http.StatusForbidden, "forbidden", "service account access denied")
	}))
	defer server.Close()

	collector := newTestGCPCollector(server)

	inv := Inventory{
		Provider:  ProviderGCP,
		ProjectID: "test-project",
	}

	count, err := collector.collectServiceAccounts(
		context.Background(),
		server.Client(),
		server.URL+"/iam/v1",
		"test-project",
		&inv,
	)

	if err == nil {
		t.Fatal("expected permission denied error")
	}

	if count != 0 {
		t.Errorf("expected zero collected accounts, got %d", count)
	}

	if len(inv.Resources) != 0 {
		t.Errorf("expected no resources, got %d", len(inv.Resources))
	}

	if classifyGCPError(err) != CoveragePermissionDenied {
		t.Errorf("expected permission_denied classification, got %s",
			classifyGCPError(err))
	}
}

func TestGCPDiscoverServiceAccountsPartialPagination(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost &&
			r.URL.Path == "/v3/projects/test-project:getIamPolicy":
			writeJSON(w, http.StatusOK, gcpIAMPolicyResponse{Version: 3})

		case r.URL.Path == "/v3/projects/test-project":
			serveGCPProject(w)

		case r.URL.Path == "/v1/projects/test-project/services":
			writeJSON(w, http.StatusOK, gcpServicesResponse{
				Services: []gcpServiceResponse{
					{Name: "iam.googleapis.com", State: "ENABLED"},
				},
			})

		case r.URL.Path == "/iam/v1/projects/test-project/serviceAccounts":
			if r.URL.Query().Get("pageToken") == "" {
				writeJSON(w, http.StatusOK, gcpServiceAccountsResponse{
					Accounts: []gcpServiceAccount{
						{
							Name:  "projects/test-project/serviceAccounts/first@test-project.iam.gserviceaccount.com",
							Email: "first@test-project.iam.gserviceaccount.com",
						},
					},
					NextPageToken: "next-page",
				})
				return
			}

			writeGCPError(w, http.StatusForbidden, "forbidden", "service account second page denied")

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

	var coverage Coverage
	for _, item := range inv.Coverage {
		if item.Category == "iam_service_accounts" {
			coverage = item
			break
		}
	}

	if coverage.Category == "" {
		t.Fatal("iam_service_accounts coverage record not found")
	}

	if coverage.Status != CoveragePartial {
		t.Errorf("expected partial coverage, got %s", coverage.Status)
	}

	if coverage.ResourceCount != 1 {
		t.Errorf("expected one collected service account, got %d", coverage.ResourceCount)
	}

	if !strings.Contains(coverage.Message, "service account second page denied") {
		t.Errorf("expected pagination error message, got %q", coverage.Message)
	}

	found := false
	for _, resource := range inv.Resources {
		if resource.Type == "gcp.iam.service_account" &&
			resource.Name == "first@test-project.iam.gserviceaccount.com" {
			found = true
			break
		}
	}

	if !found {
		t.Error("expected first-page service account to be retained")
	}
}

func TestGCPDiscoverServiceAccountsPermissionDenied(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost &&
			r.URL.Path == "/v3/projects/test-project:getIamPolicy":
			writeJSON(w, http.StatusOK, gcpIAMPolicyResponse{Version: 3})

		case r.URL.Path == "/v3/projects/test-project":
			serveGCPProject(w)

		case r.URL.Path == "/v1/projects/test-project/services":
			writeJSON(w, http.StatusOK, gcpServicesResponse{
				Services: []gcpServiceResponse{
					{Name: "iam.googleapis.com", State: "ENABLED"},
				},
			})

		case r.URL.Path == "/iam/v1/projects/test-project/serviceAccounts":
			writeGCPError(w, http.StatusForbidden, "forbidden", "service account access denied")

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

	var coverage Coverage
	for _, item := range inv.Coverage {
		if item.Category == "iam_service_accounts" {
			coverage = item
			break
		}
	}

	if coverage.Category == "" {
		t.Fatal("iam_service_accounts coverage record not found")
	}

	if coverage.Status != CoveragePermissionDenied {
		t.Errorf("expected permission_denied, got %s", coverage.Status)
	}

	if coverage.ResourceCount != 0 {
		t.Errorf("expected zero service accounts, got %d", coverage.ResourceCount)
	}

	if !strings.Contains(coverage.Message, "service account access denied") {
		t.Errorf("expected permission error message, got %q", coverage.Message)
	}
}

func TestGCPCollectServiceAccountKeysPagination(t *testing.T) {
	pageRequests := 0

	email := "test-sa@test-project.iam.gserviceaccount.com"
	expectedPath := "/iam/v1/projects/test-project/serviceAccounts/" + email + "/keys"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("unexpected authorization header: %q", r.Header.Get("Authorization"))
		}

		if r.URL.Path != expectedPath {
			http.NotFound(w, r)
			return
		}

		if r.URL.Query().Get("keyTypes") != "USER_MANAGED" {
			t.Errorf("expected USER_MANAGED keys, got %q", r.URL.Query().Get("keyTypes"))
		}

		if r.URL.Query().Get("pageSize") != "100" {
			t.Errorf("expected pageSize 100, got %q", r.URL.Query().Get("pageSize"))
		}

		pageRequests++

		switch r.URL.Query().Get("pageToken") {
		case "":
			writeJSON(w, http.StatusOK, gcpServiceAccountKeysResponse{
				Keys: []gcpServiceAccountKey{
					{
						Name:            "projects/test-project/serviceAccounts/" + email + "/keys/key-1",
						KeyType:         "USER_MANAGED",
						KeyOrigin:       "USER_PROVIDED",
						ValidAfterTime:  "2026-01-01T00:00:00Z",
						ValidBeforeTime: "2027-01-01T00:00:00Z",
						Disabled:        false,
					},
				},
				NextPageToken: "page-2",
			})

		case "page-2":
			writeJSON(w, http.StatusOK, gcpServiceAccountKeysResponse{
				Keys: []gcpServiceAccountKey{
					{
						Name:            "projects/test-project/serviceAccounts/" + email + "/keys/key-2",
						KeyType:         "USER_MANAGED",
						KeyOrigin:       "GOOGLE_PROVIDED",
						ValidAfterTime:  "2026-02-01T00:00:00Z",
						ValidBeforeTime: "2027-02-01T00:00:00Z",
						Disabled:        true,
						DisableReason:   "USER_INITIATED",
					},
				},
			})

		default:
			t.Errorf("unexpected page token: %q", r.URL.Query().Get("pageToken"))
			http.Error(w, "unexpected page token", http.StatusBadRequest)
		}
	}))
	defer server.Close()

	collector := newTestGCPCollector(server)

	inv := Inventory{
		Provider:  ProviderGCP,
		ProjectID: "test-project",
		Resources: []Resource{
			{
				ID:       "service-account-1",
				Name:     email,
				Type:     "gcp.iam.service_account",
				Provider: ProviderGCP,
				Properties: map[string]any{
					"email": email,
				},
			},
		},
	}

	count, successfulAccounts, err := collector.collectServiceAccountKeys(
		context.Background(),
		server.Client(),
		server.URL+"/iam/v1",
		"test-project",
		&inv,
	)
	if err != nil {
		t.Fatalf("key collection failed: %v", err)
	}

	if count != 2 {
		t.Fatalf("expected 2 keys, got %d", count)
	}

	if successfulAccounts != 1 {
		t.Fatalf("expected 1 successful account, got %d", successfulAccounts)
	}

	if pageRequests != 2 {
		t.Fatalf("expected 2 page requests, got %d", pageRequests)
	}

	if len(inv.Resources) != 3 {
		t.Fatalf("expected 1 service account and 2 keys, got %d resources", len(inv.Resources))
	}

	first := inv.Resources[1]
	if first.Type != "gcp.iam.service_account_key" {
		t.Fatalf("unexpected first key resource type: %s", first.Type)
	}

	expectedFirst := map[string]any{
		"service_account_email": email,
		"key_type":              "USER_MANAGED",
		"key_origin":            "USER_PROVIDED",
		"valid_after_time":      "2026-01-01T00:00:00Z",
		"valid_before_time":     "2027-01-01T00:00:00Z",
		"disabled":              false,
		"disable_reason":        "",
	}

	for key, want := range expectedFirst {
		if got := first.Properties[key]; got != want {
			t.Errorf("first key property %q: expected %v, got %v", key, want, got)
		}
	}

	second := inv.Resources[2]
	if second.Properties["disabled"] != true {
		t.Error("expected second key to be disabled")
	}

	if second.Properties["disable_reason"] != "USER_INITIATED" {
		t.Errorf("unexpected disable reason: %v", second.Properties["disable_reason"])
	}
}

func TestGCPCollectServiceAccountKeysPartialFailure(t *testing.T) {
	firstEmail := "first@test-project.iam.gserviceaccount.com"
	secondEmail := "second@test-project.iam.gserviceaccount.com"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, firstEmail) {
			writeGCPError(w, http.StatusForbidden, "forbidden", "first account key access denied")
			return
		}

		if strings.Contains(r.URL.Path, secondEmail) {
			writeJSON(w, http.StatusOK, gcpServiceAccountKeysResponse{
				Keys: []gcpServiceAccountKey{
					{
						Name:      "projects/test-project/serviceAccounts/" + secondEmail + "/keys/key-2",
						KeyType:   "USER_MANAGED",
						KeyOrigin: "GOOGLE_PROVIDED",
					},
				},
			})
			return
		}

		http.NotFound(w, r)
	}))
	defer server.Close()

	collector := newTestGCPCollector(server)

	inv := Inventory{
		Provider:  ProviderGCP,
		ProjectID: "test-project",
		Resources: []Resource{
			{
				Name:     firstEmail,
				Type:     "gcp.iam.service_account",
				Provider: ProviderGCP,
				Properties: map[string]any{
					"email": firstEmail,
				},
			},
			{
				Name:     secondEmail,
				Type:     "gcp.iam.service_account",
				Provider: ProviderGCP,
				Properties: map[string]any{
					"email": secondEmail,
				},
			},
		},
	}

	count, successfulAccounts, err := collector.collectServiceAccountKeys(
		context.Background(),
		server.Client(),
		server.URL+"/iam/v1",
		"test-project",
		&inv,
	)

	if err == nil {
		t.Fatal("expected partial collection error")
	}

	if !strings.Contains(err.Error(), "first account key access denied") {
		t.Errorf("unexpected error message: %v", err)
	}

	if classifyGCPError(err) != CoveragePermissionDenied {
		t.Errorf("expected permission_denied classification, got %s",
			classifyGCPError(err))
	}

	if count != 1 {
		t.Errorf("expected 1 successfully collected key, got %d", count)
	}

	if successfulAccounts != 1 {
		t.Errorf("expected 1 successful account, got %d", successfulAccounts)
	}

	if len(inv.Resources) != 3 {
		t.Fatalf("expected 2 accounts and 1 key, got %d resources", len(inv.Resources))
	}

	if inv.Resources[2].Type != "gcp.iam.service_account_key" {
		t.Errorf("expected successful key resource to be preserved, got %s",
			inv.Resources[2].Type)
	}
}

func TestGCPCollectServiceAccountKeysEmpty(t *testing.T) {
	email := "empty@test-project.iam.gserviceaccount.com"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, gcpServiceAccountKeysResponse{
			Keys: []gcpServiceAccountKey{},
		})
	}))
	defer server.Close()

	collector := newTestGCPCollector(server)

	inv := Inventory{
		Provider:  ProviderGCP,
		ProjectID: "test-project",
		Resources: []Resource{
			{
				Name:     email,
				Type:     "gcp.iam.service_account",
				Provider: ProviderGCP,
				Properties: map[string]any{
					"email": email,
				},
			},
		},
	}

	count, successfulAccounts, err := collector.collectServiceAccountKeys(
		context.Background(),
		server.Client(),
		server.URL+"/iam/v1",
		"test-project",
		&inv,
	)

	if err != nil {
		t.Fatalf("empty key collection should succeed: %v", err)
	}

	if count != 0 {
		t.Errorf("expected zero keys, got %d", count)
	}

	if successfulAccounts != 1 {
		t.Errorf("expected 1 successfully inspected account, got %d", successfulAccounts)
	}

	if len(inv.Resources) != 1 {
		t.Errorf("expected only the service account resource, got %d resources", len(inv.Resources))
	}
}
