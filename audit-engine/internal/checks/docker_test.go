package checks

import (
	"fmt"
	"strings"
	"testing"

	"github.com/cloudbusket/ai-auditor/audit-engine/internal/docker"
	"github.com/cloudbusket/ai-auditor/audit-engine/internal/inventory"
)

func dockerTestInventory() *inventory.Inventory {
	return &inventory.Inventory{
		Docker: &docker.Inventory{
			CLIAvailable:    true,
			DaemonAvailable: true,
		},
	}
}

func findDockerFinding(t *testing.T, r Report, id string) Finding {
	t.Helper()

	for _, finding := range r.Findings {
		if finding.ID == id {
			return finding
		}
	}

	t.Fatalf("finding %s not found", id)
	return Finding{}
}

func TestCheckDockerFilesystemThresholds(t *testing.T) {
	tests := []struct {
		usage uint64
		want  Status
	}{
		{79, StatusPass},
		{80, StatusWarning},
		{89, StatusWarning},
		{90, StatusCritical},
		{97, StatusCritical},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("usage_%d", tt.usage), func(t *testing.T) {
			r := NewReport()
			inv := dockerTestInventory()
			inv.Docker.DockerRootDir = "/var/lib/docker"
			inv.Docker.FilesystemSizeGB = 100
			inv.Docker.FilesystemUsedGB = tt.usage
			inv.Docker.FilesystemUsedPercent = tt.usage

			checkDocker(&r, inv)

			finding := findDockerFinding(t, r, "DCK006")
			if finding.Status != tt.want {
				t.Errorf("usage %d: expected %q, got %q",
					tt.usage, tt.want, finding.Status)
			}
		})
	}
}

func TestCheckDockerFilesystemMissingRootDirectory(t *testing.T) {
	r := NewReport()
	inv := dockerTestInventory()
	inv.Docker.FilesystemUsedPercent = 50

	checkDocker(&r, inv)

	finding := findDockerFinding(t, r, "DCK006")
	if finding.Status != StatusWarning {
		t.Errorf("expected %q, got %q", StatusWarning, finding.Status)
	}
}

func TestCheckDockerStorageCollected(t *testing.T) {
	r := NewReport()
	inv := dockerTestInventory()
	inv.Docker.Storage = []docker.StorageEntry{
		{
			Type:        "Images",
			TotalCount:  "7",
			Active:      "3",
			Size:        "10.91GB",
			Reclaimable: "2.204GB (20%)",
		},
	}

	checkDocker(&r, inv)

	finding := findDockerFinding(t, r, "DCK005")
	if finding.Status != StatusPass {
		t.Fatalf("expected %q, got %q", StatusPass, finding.Status)
	}
	for _, expected := range []string{"Images", "10.91GB", "7 items", "3 active"} {
		if !strings.Contains(finding.Message, expected) {
			t.Errorf("expected DCK005 message to contain %q; got %q",
				expected, finding.Message)
		}
	}
}

func TestCheckDockerStorageMissing(t *testing.T) {
	r := NewReport()
	inv := dockerTestInventory()

	checkDocker(&r, inv)

	finding := findDockerFinding(t, r, "DCK005")
	if finding.Status != StatusWarning {
		t.Errorf("expected %q, got %q", StatusWarning, finding.Status)
	}
	if !strings.Contains(finding.Message, "could not be collected") {
		t.Errorf("unexpected DCK005 message: %q", finding.Message)
	}
}

func TestCheckDockerUnhealthyContainerEvidence(t *testing.T) {
	r := NewReport()
	inv := dockerTestInventory()

	inv.Docker.Containers = []docker.Container{
		{
			ID:      "abc123",
			Name:    "api-container",
			Image:   "my-api:latest",
			State:   "running",
			Status:  "Up 5 minutes (unhealthy)",
			Running: true,
			Health:  "unhealthy",
		},
	}

	checkDocker(&r, inv)

	f := findDockerFinding(t, r, "DCK002")

	if f.Status != StatusCritical {
		t.Errorf("expected critical status, got %q", f.Status)
	}
	if f.Source != "native" {
		t.Errorf("expected native source, got %q", f.Source)
	}
	if f.Asset != "Docker containers" {
		t.Errorf("expected Docker containers asset, got %q", f.Asset)
	}

	if f.Evidence["unhealthy_count"] != 1 {
		t.Errorf("expected one unhealthy container, got %v",
			f.Evidence["unhealthy_count"])
	}

	containers, ok := f.Evidence["containers"].([]map[string]any)
	if !ok || len(containers) != 1 {
		t.Fatalf("expected one container evidence entry, got %v",
			f.Evidence["containers"])
	}

	expected := map[string]any{
		"id":      "abc123",
		"name":    "api-container",
		"image":   "my-api:latest",
		"state":   "running",
		"status":  "Up 5 minutes (unhealthy)",
		"running": true,
		"health":  "unhealthy",
	}

	for key, want := range expected {
		if got := containers[0][key]; got != want {
			t.Errorf("evidence[%q]: expected %v, got %v", key, want, got)
		}
	}
}

func TestCheckDockerStoppedContainerEvidence(t *testing.T) {
	r := NewReport()
	inv := dockerTestInventory()

	inv.Docker.Containers = []docker.Container{
		{
			ID:      "def456",
			Name:    "worker-container",
			Image:   "worker:v1",
			State:   "exited",
			Status:  "Exited (1) 2 hours ago",
			Running: false,
		},
	}

	checkDocker(&r, inv)

	f := findDockerFinding(t, r, "DCK003")

	if f.Status != StatusWarning {
		t.Errorf("expected warning status, got %q", f.Status)
	}
	if f.Source != "native" {
		t.Errorf("expected native source, got %q", f.Source)
	}
	if f.Asset != "Docker containers" {
		t.Errorf("expected Docker containers asset, got %q", f.Asset)
	}

	if f.Evidence["stopped_count"] != 1 {
		t.Errorf("expected one stopped container, got %v",
			f.Evidence["stopped_count"])
	}

	containers, ok := f.Evidence["containers"].([]map[string]any)
	if !ok || len(containers) != 1 {
		t.Fatalf("expected one container evidence entry, got %v",
			f.Evidence["containers"])
	}

	if containers[0]["id"] != "def456" {
		t.Errorf("expected container ID def456, got %v", containers[0]["id"])
	}
	if containers[0]["name"] != "worker-container" {
		t.Errorf("expected worker-container, got %v", containers[0]["name"])
	}
	if containers[0]["state"] != "exited" {
		t.Errorf("expected exited state, got %v", containers[0]["state"])
	}
}

func TestCheckDockerHealthyContainersEvidence(t *testing.T) {
	r := NewReport()
	inv := dockerTestInventory()

	inv.Docker.Containers = []docker.Container{
		{
			ID:      "healthy123",
			Name:    "web-container",
			Image:   "web:latest",
			State:   "running",
			Status:  "Up 10 minutes (healthy)",
			Running: true,
			Health:  "healthy",
		},
	}

	checkDocker(&r, inv)

	unhealthy := findDockerFinding(t, r, "DCK002")
	stopped := findDockerFinding(t, r, "DCK003")

	if unhealthy.Status != StatusPass {
		t.Errorf("expected DCK002 pass, got %q", unhealthy.Status)
	}
	if stopped.Status != StatusPass {
		t.Errorf("expected DCK003 pass, got %q", stopped.Status)
	}

	if unhealthy.Evidence["unhealthy_count"] != 0 {
		t.Errorf("expected zero unhealthy containers, got %v",
			unhealthy.Evidence["unhealthy_count"])
	}
	if stopped.Evidence["stopped_count"] != 0 {
		t.Errorf("expected zero stopped containers, got %v",
			stopped.Evidence["stopped_count"])
	}
}
func TestCheckDockerFilesystemEvidence(t *testing.T) {
	tests := []struct {
		name   string
		usage  uint64
		status Status
	}{
		{"healthy", 50, StatusPass},
		{"warning", 85, StatusWarning},
		{"critical", 95, StatusCritical},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewReport()
			inv := dockerTestInventory()

			inv.Docker.DockerRootDir = "/var/lib/docker"
			inv.Docker.FilesystemSizeGB = 200
			inv.Docker.FilesystemUsedGB = 170
			inv.Docker.FilesystemFreeGB = 30
			inv.Docker.FilesystemUsedPercent = tt.usage

			checkDocker(&r, inv)

			f := findDockerFinding(t, r, "DCK006")

			if f.Status != tt.status {
				t.Fatalf("expected status %q, got %q", tt.status, f.Status)
			}

			expected := map[string]any{
				"docker_root_dir":         "/var/lib/docker",
				"filesystem_size_gb":      uint64(200),
				"filesystem_used_gb":      uint64(170),
				"filesystem_free_gb":      uint64(30),
				"filesystem_used_percent": tt.usage,
			}

			for key, want := range expected {
				if got := f.Evidence[key]; got != want {
					t.Errorf("evidence[%q]: expected %v, got %v", key, want, got)
				}
			}

			if f.Asset != "Docker filesystem" {
				t.Errorf("expected Docker filesystem asset, got %q", f.Asset)
			}

			if f.Source != "native" {
				t.Errorf("expected native source, got %q", f.Source)
			}
		})
	}
}

func TestCheckDockerFilesystemMissingRootEvidence(t *testing.T) {
	r := NewReport()
	inv := dockerTestInventory()
	inv.Docker.FilesystemUsedPercent = 50

	checkDocker(&r, inv)

	f := findDockerFinding(t, r, "DCK006")

	if f.Status != StatusWarning {
		t.Fatalf("expected warning, got %q", f.Status)
	}

	if f.Evidence["docker_root_dir"] != "" {
		t.Errorf("expected empty Docker root directory, got %v",
			f.Evidence["docker_root_dir"])
	}

	if f.Evidence["filesystem_used_percent"] != uint64(50) {
		t.Errorf("expected filesystem usage 50, got %v",
			f.Evidence["filesystem_used_percent"])
	}
}

func TestCheckDockerStorageEvidence(t *testing.T) {
	r := NewReport()
	inv := dockerTestInventory()

	inv.Docker.Storage = []docker.StorageEntry{
		{
			Type:        "Images",
			TotalCount:  "7",
			Active:      "3",
			Size:        "10.91GB",
			Reclaimable: "2.204GB (20%)",
		},
	}

	checkDocker(&r, inv)

	f := findDockerFinding(t, r, "DCK005")

	if f.Evidence["storage_entry_count"] != 1 {
		t.Errorf("expected one storage entry, got %v",
			f.Evidence["storage_entry_count"])
	}

	storage, ok := f.Evidence["storage"].([]map[string]any)
	if !ok || len(storage) != 1 {
		t.Fatalf("expected one storage evidence entry, got %v",
			f.Evidence["storage"])
	}

	expected := map[string]any{
		"type":        "Images",
		"total_count": "7",
		"active":      "3",
		"size":        "10.91GB",
		"reclaimable": "2.204GB (20%)",
	}

	for key, want := range expected {
		if got := storage[0][key]; got != want {
			t.Errorf("storage evidence[%q]: expected %v, got %v",
				key, want, got)
		}
	}
}

func TestCheckDockerStorageMissingEvidence(t *testing.T) {
	r := NewReport()
	inv := dockerTestInventory()

	checkDocker(&r, inv)

	f := findDockerFinding(t, r, "DCK005")

	if f.Evidence["storage_entry_count"] != 0 {
		t.Errorf("expected zero storage entries, got %v",
			f.Evidence["storage_entry_count"])
	}

	storage, ok := f.Evidence["storage"].([]map[string]any)
	if !ok || len(storage) != 0 {
		t.Errorf("expected empty storage evidence, got %v",
			f.Evidence["storage"])
	}
}

func TestCheckDockerIncompleteInventoryEvidence(t *testing.T) {
	r := NewReport()
	inv := dockerTestInventory()

	inv.Docker.Error = "image collection failed"
	inv.Docker.Containers = []docker.Container{{ID: "container-1"}}
	inv.Docker.Images = []docker.Image{{ID: "image-1"}}
	inv.Docker.Networks = []docker.Network{{ID: "network-1"}}
	inv.Docker.Volumes = []docker.Volume{{Name: "volume-1"}}
	inv.Docker.Storage = []docker.StorageEntry{{Type: "Images"}}

	checkDocker(&r, inv)

	f := findDockerFinding(t, r, "DCK004")

	if f.Status != StatusWarning {
		t.Fatalf("expected warning status, got %q", f.Status)
	}

	expected := map[string]any{
		"error":               "image collection failed",
		"cli_available":       true,
		"daemon_available":    true,
		"container_count":     1,
		"image_count":         1,
		"network_count":       1,
		"volume_count":        1,
		"storage_entry_count": 1,
	}

	for key, want := range expected {
		if got := f.Evidence[key]; got != want {
			t.Errorf("DCK004 evidence[%q]: expected %v, got %v",
				key, want, got)
		}
	}
}
