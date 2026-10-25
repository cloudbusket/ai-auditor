package checks

import (
	"testing"

	"github.com/cloudbusket/ai-auditor/audit-engine/internal/inventory"
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
