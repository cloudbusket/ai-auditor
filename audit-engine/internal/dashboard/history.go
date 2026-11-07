package dashboard

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cloudbusket/ai-auditor/audit-engine/internal/checks"
)

const historyRetention = 100

type HistoryStore struct {
	dir string
	mu  sync.Mutex
}

type HistoryRecord struct {
	ID        string        `json:"id"`
	CreatedAt time.Time     `json:"created_at"`
	Report    checks.Report `json:"report"`
}

type HistorySummary struct {
	ID           string                `json:"id"`
	CreatedAt    time.Time             `json:"created_at"`
	Overall      checks.Status         `json:"overall_status"`
	Summary      checks.Summary        `json:"summary"`
	Modules      []checks.ModuleResult `json:"modules"`
	FindingCount int                   `json:"finding_count"`
}

func NewHistoryStore(dir string) (*HistoryStore, error) {
	if strings.TrimSpace(dir) == "" {
		dir = os.Getenv("AUDITOR_HISTORY_DIR")
	}

	if strings.TrimSpace(dir) == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("resolve home directory: %w", err)
		}
		dir = filepath.Join(home, ".local", "share", "cloudbusket-auditor", "history")
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create scan history directory: %w", err)
	}

	if err := os.Chmod(dir, 0700); err != nil {
		return nil, fmt.Errorf("secure scan history directory: %w", err)
	}

	return &HistoryStore{dir: dir}, nil
}

func (s *HistoryStore) Save(report checks.Report) (HistoryRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var randomID [8]byte
	if _, err := rand.Read(randomID[:]); err != nil {
		return HistoryRecord{}, fmt.Errorf("generate scan ID: %w", err)
	}

	now := time.Now().UTC()
	if report.GeneratedAt.IsZero() {
		report.GeneratedAt = now
	}

	record := HistoryRecord{
		ID:        hex.EncodeToString(randomID[:]),
		CreatedAt: now,
		Report:    report,
	}

	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return HistoryRecord{}, fmt.Errorf("encode scan report: %w", err)
	}

	tmp, err := os.CreateTemp(s.dir, ".scan-*.tmp")
	if err != nil {
		return HistoryRecord{}, fmt.Errorf("create temporary history file: %w", err)
	}

	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return HistoryRecord{}, fmt.Errorf("secure temporary history file: %w", err)
	}

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return HistoryRecord{}, fmt.Errorf("write scan history: %w", err)
	}

	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return HistoryRecord{}, fmt.Errorf("sync scan history: %w", err)
	}

	if err := tmp.Close(); err != nil {
		return HistoryRecord{}, fmt.Errorf("close scan history: %w", err)
	}

	finalPath := filepath.Join(s.dir, record.ID+".json")
	if err := os.Rename(tmpName, finalPath); err != nil {
		return HistoryRecord{}, fmt.Errorf("save scan history: %w", err)
	}

	if err := s.pruneLocked(); err != nil {
		return record, fmt.Errorf("scan saved but history retention failed: %w", err)
	}

	return record, nil
}

func (s *HistoryStore) List() ([]HistorySummary, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("read scan history: %w", err)
	}

	summaries := make([]HistorySummary, 0)

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		id := strings.TrimSuffix(entry.Name(), ".json")
		if !validHistoryID(id) {
			continue
		}

		data, err := os.ReadFile(filepath.Join(s.dir, entry.Name()))
		if err != nil {
			continue
		}

		var record HistoryRecord
		if err := json.Unmarshal(data, &record); err != nil || record.ID != id {
			continue
		}

		summaries = append(summaries, HistorySummary{
			ID:           record.ID,
			CreatedAt:    record.CreatedAt,
			Overall:      record.Report.OverallStatus,
			Summary:      record.Report.Summary,
			Modules:      record.Report.Modules,
			FindingCount: len(record.Report.Findings),
		})
	}

	sort.Slice(summaries, func(i, j int) bool {
		return summaries[i].CreatedAt.After(summaries[j].CreatedAt)
	})

	return summaries, nil
}

func (s *HistoryStore) Get(id string) (HistoryRecord, error) {
	if !validHistoryID(id) {
		return HistoryRecord{}, errors.New("invalid scan ID")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(filepath.Join(s.dir, id+".json"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return HistoryRecord{}, os.ErrNotExist
		}
		return HistoryRecord{}, fmt.Errorf("read scan history: %w", err)
	}

	var record HistoryRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return HistoryRecord{}, fmt.Errorf("decode scan history: %w", err)
	}

	if record.ID != id {
		return HistoryRecord{}, errors.New("scan history ID mismatch")
	}

	return record, nil
}

func (s *HistoryStore) pruneLocked() error {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return err
	}

	type fileInfo struct {
		path    string
		modTime time.Time
	}

	var files []fileInfo

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		id := strings.TrimSuffix(entry.Name(), ".json")
		if !validHistoryID(id) {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		files = append(files, fileInfo{
			path:    filepath.Join(s.dir, entry.Name()),
			modTime: info.ModTime(),
		})
	}

	sort.Slice(files, func(i, j int) bool {
		return files[i].modTime.After(files[j].modTime)
	})

	if len(files) <= historyRetention {
		return nil
	}

	for _, file := range files[historyRetention:] {
		if err := os.Remove(file.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}

	return nil
}

func validHistoryID(id string) bool {
	if len(id) != 16 {
		return false
	}

	_, err := hex.DecodeString(id)
	return err == nil
}
