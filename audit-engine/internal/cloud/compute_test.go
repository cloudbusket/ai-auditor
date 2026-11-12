package cloud

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestResourceNameFromURL(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "full GCP zone URL",
			input: "https://www.googleapis.com/compute/v1/projects/test-project/zones/us-west1-b",
			want:  "us-west1-b",
		},
		{
			name:  "machine type URL",
			input: "zones/us-west1-b/machineTypes/e2-medium",
			want:  "e2-medium",
		},
		{
			name:  "disk type URL",
			input: "zones/us-west1-b/diskTypes/pd-balanced",
			want:  "pd-balanced",
		},
		{
			name:  "region URL",
			input: "https://www.googleapis.com/compute/v1/projects/test-project/regions/us-west1",
			want:  "us-west1",
		},
		{
			name:  "empty value",
			input: "",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resourceNameFromURL(tt.input); got != tt.want {
				t.Errorf("resourceNameFromURL(%q) = %q, want %q",
					tt.input, got, tt.want)
			}
		})
	}
}

func TestRegionFromZone(t *testing.T) {
	tests := []struct {
		name string
		zone string
		want string
	}{
		{
			name: "full GCP zone URL",
			zone: "https://www.googleapis.com/compute/v1/projects/test-project/zones/us-west1-b",
			want: "us-west1",
		},
		{
			name: "short zone path",
			zone: "zones/us-central1-a",
			want: "us-central1",
		},
		{
			name: "zone name",
			zone: "asia-south1-c",
			want: "asia-south1",
		},
		{
			name: "empty zone",
			zone: "",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := regionFromZone(tt.zone); got != tt.want {
				t.Errorf("regionFromZone(%q) = %q, want %q",
					tt.zone, got, tt.want)
			}
		})
	}
}

func TestCollectComputeInstancesPartialPagination(t *testing.T) {
	requestedNextPage := false

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("pageToken") == "next-page" {
			requestedNextPage = true
			writeGCPError(w, 403, "forbidden", "second page denied")
			return
		}

		writeJSON(w, 200, map[string]any{
			"items": map[string]any{
				"zones/us-west1-b": map[string]any{
					"instances": []map[string]any{
						{
							"id":          "111",
							"name":        "test-vm",
							"machineType": "zones/us-west1-b/machineTypes/e2-medium",
							"zone":        "zones/us-west1-b",
							"status":      "RUNNING",
						},
					},
				},
			},
			"nextPageToken": "next-page",
		})
	}))
	defer server.Close()

	collector := newTestGCPCollector(server)
	inv := Inventory{Provider: ProviderGCP}

	count, err := collector.collectComputeInstances(
		context.Background(),
		server.Client(),
		server.URL+"/compute/v1",
		"test-project",
		&inv,
	)

	if err == nil {
		t.Fatal("expected pagination error")
	}

	if !requestedNextPage {
		t.Fatal("expected collector to request the second page")
	}

	if count != 1 {
		t.Errorf("expected one collected instance, got %d", count)
	}

	if len(inv.Resources) != 1 {
		t.Fatalf("expected one retained VM resource, got %d", len(inv.Resources))
	}

	if inv.Resources[0].Name != "test-vm" {
		t.Errorf("expected test-vm, got %q", inv.Resources[0].Name)
	}

	coverage := makeComputeCoverage(
		"compute_instances",
		count,
		err,
		time.Now(),
		time.Now(),
	)

	if coverage.Status != CoveragePartial {
		t.Errorf("expected partial coverage, got %s", coverage.Status)
	}
}

func TestCollectComputeDisksPartialPagination(t *testing.T) {
	requestedNextPage := false

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("pageToken") == "next-page" {
			requestedNextPage = true
			writeGCPError(w, 403, "forbidden", "second page denied")
			return
		}

		writeJSON(w, 200, map[string]any{
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
			"nextPageToken": "next-page",
		})
	}))
	defer server.Close()

	collector := newTestGCPCollector(server)
	inv := Inventory{Provider: ProviderGCP}

	count, err := collector.collectComputeDisks(
		context.Background(),
		server.Client(),
		server.URL+"/compute/v1",
		"test-project",
		&inv,
	)

	if err == nil {
		t.Fatal("expected pagination error")
	}

	if !requestedNextPage {
		t.Fatal("expected collector to request the second page")
	}

	if count != 1 {
		t.Errorf("expected one collected disk, got %d", count)
	}

	if len(inv.Resources) != 1 {
		t.Fatalf("expected one retained disk resource, got %d", len(inv.Resources))
	}

	if inv.Resources[0].Name != "test-disk" {
		t.Errorf("expected test-disk, got %q", inv.Resources[0].Name)
	}

	coverage := makeComputeCoverage(
		"compute_disks",
		count,
		err,
		time.Now(),
		time.Now(),
	)

	if coverage.Status != CoveragePartial {
		t.Errorf("expected partial coverage, got %s", coverage.Status)
	}
}
