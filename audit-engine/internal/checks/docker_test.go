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
