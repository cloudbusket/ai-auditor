package checks

import (
	"testing"

	"github.com/cloudbusket/ai-auditor/audit-engine/internal/inventory"
	"github.com/shirou/gopsutil/v3/mem"
)

func TestCheckRootDiskThresholds(t *testing.T) {
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
		r := NewReport()
		inv := &inventory.Inventory{
			Disk: []inventory.DiskInfo{
				{Mount: "/", SizeGB: 100, UsedGB: tt.usage, UsedPercent: tt.usage},
			},
		}

		checkRootDisk(&r, inv)

		if len(r.Findings) != 1 {
			t.Fatalf("usage %d: expected one finding, got %d", tt.usage, len(r.Findings))
		}
		if r.Findings[0].Status != tt.want {
			t.Errorf("usage %d: expected %q, got %q",
				tt.usage, tt.want, r.Findings[0].Status)
		}
	}
}

func TestCheckRootDiskMissing(t *testing.T) {
	r := NewReport()
	inv := &inventory.Inventory{
		Disk: []inventory.DiskInfo{{Mount: "/data", UsedPercent: 50}},
	}

	checkRootDisk(&r, inv)

	if r.OverallStatus != StatusError {
		t.Fatalf("expected error, got %q", r.OverallStatus)
	}
}

func TestCheckServices(t *testing.T) {
	tests := []struct {
		name     string
		services []inventory.ServiceInfo
		want     Status
		count    int
	}{
		{
			name: "healthy",
			services: []inventory.ServiceInfo{
				{Name: "ssh", State: "running", SubState: "running"},
			},
			want: StatusPass, count: 1,
		},
		{
			name: "failed",
			services: []inventory.ServiceInfo{
				{Name: "example.service", State: "failed", SubState: "failed"},
			},
			want: StatusCritical, count: 1,
		},
		{
			name: "case insensitive",
			services: []inventory.ServiceInfo{
				{Name: "example.service", State: "FAILED"},
			},
			want: StatusCritical, count: 1,
		},
		{
			name: "multiple failures",
			services: []inventory.ServiceInfo{
				{Name: "one.service", State: "failed"},
				{Name: "two.service", SubState: "failed"},
			},
			want: StatusCritical, count: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewReport()
			inv := &inventory.Inventory{Services: tt.services}

			checkServices(&r, inv)

			if r.OverallStatus != tt.want {
				t.Errorf("expected status %q, got %q", tt.want, r.OverallStatus)
			}
			if len(r.Findings) != tt.count {
				t.Errorf("expected %d findings, got %d", tt.count, len(r.Findings))
			}
		})
	}
}
func TestCheckRootDiskEvidence(t *testing.T) {
	r := NewReport()

	inv := &inventory.Inventory{
		Disk: []inventory.DiskInfo{
			{
				Device:      "/dev/sda1",
				Mount:       "/",
				FSType:      "ext4",
				SizeGB:      100,
				UsedGB:      85,
				FreeGB:      15,
				UsedPercent: 85,
			},
		},
	}

	checkRootDisk(&r, inv)

	if len(r.Findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(r.Findings))
	}

	f := r.Findings[0]

	if f.Source != "native" {
		t.Errorf("expected source native, got %q", f.Source)
	}

	if f.Asset != "/" {
		t.Errorf("expected asset /, got %q", f.Asset)
	}

	if f.Status != StatusWarning {
		t.Errorf("expected warning status, got %q", f.Status)
	}

	if f.Description == "" {
		t.Error("expected finding description to be populated")
	}

	if f.Evidence == nil {
		t.Fatal("expected disk evidence, got nil")
	}

	expected := map[string]any{
		"device":       "/dev/sda1",
		"mount":        "/",
		"filesystem":   "ext4",
		"size_gb":      uint64(100),
		"used_gb":      uint64(85),
		"free_gb":      uint64(15),
		"used_percent": uint64(85),
	}

	for key, want := range expected {
		if got := f.Evidence[key]; got != want {
			t.Errorf("evidence[%q]: expected %v, got %v", key, want, got)
		}
	}
}

func TestCheckMemoryUsage(t *testing.T) {
	tests := []struct {
		name string
		pct  float64
		want Status
	}{
		{"normal", 70, StatusPass},
		{"warning threshold", 85, StatusWarning},
		{"high warning", 94, StatusWarning},
		{"critical threshold", 95, StatusCritical},
		{"critical usage", 98, StatusCritical},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewReport()

			vm := &mem.VirtualMemoryStat{
				Total:       16 * 1024 * 1024 * 1024,
				Used:        14 * 1024 * 1024 * 1024,
				Available:   2 * 1024 * 1024 * 1024,
				Free:        1 * 1024 * 1024 * 1024,
				UsedPercent: tt.pct,
			}

			checkMemoryUsage(&r, vm)

			if len(r.Findings) != 1 {
				t.Fatalf("expected one finding, got %d", len(r.Findings))
			}

			f := r.Findings[0]

			if f.Status != tt.want {
				t.Errorf("expected status %q, got %q", tt.want, f.Status)
			}

			if f.Source != "native" {
				t.Errorf("expected source native, got %q", f.Source)
			}

			if f.Asset != "system memory" {
				t.Errorf("expected asset system memory, got %q", f.Asset)
			}

			if f.Evidence == nil {
				t.Fatal("expected memory evidence, got nil")
			}

			expectedEvidence := map[string]any{
				"total_bytes":     vm.Total,
				"used_bytes":      vm.Used,
				"available_bytes": vm.Available,
				"free_bytes":      vm.Free,
				"used_percent":    vm.UsedPercent,
			}

			for key, want := range expectedEvidence {
				if got := f.Evidence[key]; got != want {
					t.Errorf("evidence[%q]: expected %v, got %v", key, want, got)
				}
			}
		})
	}
}

func TestCheckServicesEvidence(t *testing.T) {
	r := NewReport()

	inv := &inventory.Inventory{
		Services: []inventory.ServiceInfo{
			{
				Name:          "nginx.service",
				Description:   "Web server",
				State:         "failed",
				SubState:      "failed",
				Enabled:       true,
				ActiveSince:   "2026-10-31T10:00:00Z",
				MainPID:       1234,
				MemoryCurrent: "1048576",
			},
		},
	}

	checkServices(&r, inv)

	if len(r.Findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(r.Findings))
	}

	f := r.Findings[0]

	if f.Status != StatusCritical {
		t.Errorf("expected critical status, got %q", f.Status)
	}
	if f.Source != "native" {
		t.Errorf("expected native source, got %q", f.Source)
	}
	if f.Asset != "nginx.service" {
		t.Errorf("expected nginx.service asset, got %q", f.Asset)
	}
	if f.Description == "" {
		t.Error("expected description to be populated")
	}

	expected := map[string]any{
		"name":           "nginx.service",
		"description":    "Web server",
		"state":          "failed",
		"sub_state":      "failed",
		"enabled":        true,
		"active_since":   "2026-10-31T10:00:00Z",
		"main_pid":       1234,
		"memory_current": "1048576",
	}

	for key, want := range expected {
		if got := f.Evidence[key]; got != want {
			t.Errorf("evidence[%q]: expected %v, got %v", key, want, got)
		}
	}
}

func TestCheckServicesHealthyEvidence(t *testing.T) {
	r := NewReport()

	inv := &inventory.Inventory{
		Services: []inventory.ServiceInfo{
			{Name: "ssh.service", State: "running"},
			{Name: "cron.service", State: "running"},
		},
	}

	checkServices(&r, inv)

	if len(r.Findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(r.Findings))
	}

	f := r.Findings[0]

	if f.Status != StatusPass {
		t.Errorf("expected pass status, got %q", f.Status)
	}
	if f.Evidence["checked_services"] != 2 {
		t.Errorf("expected 2 checked services, got %v", f.Evidence["checked_services"])
	}
	if f.Evidence["failed_services"] != 0 {
		t.Errorf("expected 0 failed services, got %v", f.Evidence["failed_services"])
	}
}
