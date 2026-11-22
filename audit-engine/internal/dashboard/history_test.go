package dashboard

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cloudbusket/ai-auditor/audit-engine/internal/checks"
)

func TestHistoryStoreReadsLegacyRecordWithoutFingerprint(t *testing.T) {
	dir := t.TempDir()

	history, err := NewHistoryStore(dir)
	if err != nil {
		t.Fatalf("create history store: %v", err)
	}

	const legacyID = "0123456789abcdef"

	legacyJSON := `{
		"id": "0123456789abcdef",
		"created_at": "2026-01-15T10:00:00Z",
		"report": {
			"generated_at": "2026-01-15T09:59:00Z",
			"overall_status": "warning",
			"summary": {
				"passed": 2,
				"warnings": 1,
				"critical": 0,
				"errors": 0
			},
			"findings": [
				{
					"id": "DISK001",
					"source": "native",
					"category": "storage",
					"asset": "root filesystem",
					"status": "warning",
					"severity": "medium",
					"message": "Root filesystem usage is elevated"
				}
			]
		}
	}`

	path := filepath.Join(dir, legacyID+".json")
	if err := os.WriteFile(path, []byte(legacyJSON), 0600); err != nil {
		t.Fatalf("write legacy history record: %v", err)
	}

	summaries, err := history.List()
	if err != nil {
		t.Fatalf("list history: %v", err)
	}

	if len(summaries) != 1 {
		t.Fatalf("expected 1 history summary, got %d", len(summaries))
	}

	if summaries[0].ID != legacyID {
		t.Fatalf("expected summary ID %q, got %q", legacyID, summaries[0].ID)
	}

	if summaries[0].FindingCount != 1 {
		t.Fatalf("expected 1 finding, got %d", summaries[0].FindingCount)
	}

	if summaries[0].Overall != checks.StatusWarning {
		t.Fatalf("expected warning status, got %q", summaries[0].Overall)
	}

	record, err := history.Get(legacyID)
	if err != nil {
		t.Fatalf("get legacy history record: %v", err)
	}

	if len(record.Report.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(record.Report.Findings))
	}

	finding := record.Report.Findings[0]

	if finding.ID != "DISK001" {
		t.Fatalf("expected finding ID DISK001, got %q", finding.ID)
	}

	if finding.Fingerprint != "" {
		t.Fatalf("expected legacy fingerprint to remain empty, got %q", finding.Fingerprint)
	}

	if finding.Message != "Root filesystem usage is elevated" {
		t.Fatalf("unexpected legacy finding message: %q", finding.Message)
	}
}

func TestHistoryStoreSaveAddsFindingFingerprint(t *testing.T) {
	history, err := NewHistoryStore(t.TempDir())
	if err != nil {
		t.Fatalf("create history store: %v", err)
	}

	record, err := history.Save(checks.Report{
		Findings: []checks.Finding{
			{
				ID:       "DISK001",
				Source:   "native",
				Category: "storage",
				Asset:    "root filesystem",
				Status:   checks.StatusWarning,
				Severity: "medium",
				Message:  "Root filesystem usage is elevated",
			},
		},
	})
	if err != nil {
		t.Fatalf("save history record: %v", err)
	}

	if len(record.Report.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(record.Report.Findings))
	}

	fingerprint := record.Report.Findings[0].Fingerprint
	if fingerprint == "" {
		t.Fatal("expected saved finding to have a fingerprint")
	}

	loaded, err := history.Get(record.ID)
	if err != nil {
		t.Fatalf("get saved history record: %v", err)
	}

	if loaded.Report.Findings[0].Fingerprint != fingerprint {
		t.Fatal("fingerprint changed after saving and loading history")
	}

	if loaded.Report.GeneratedAt.IsZero() {
		t.Fatal("expected generated_at to be populated")
	}

	if !loaded.CreatedAt.After(time.Time{}) {
		t.Fatal("expected created_at to be populated")
	}
}
