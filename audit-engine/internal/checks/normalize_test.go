package checks

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestStableFingerprintGCPBindingMemberOrder(t *testing.T) {
	first := Finding{
		ID:       "GCP001",
		Source:   "gcp",
		Category: "iam",
		Asset:    "project-a",
		Evidence: map[string]any{
			"role":    "roles/editor",
			"members": []string{"user:b@example.com", "user:a@example.com"},
			"condition": map[string]any{
				"expression": "request.time < timestamp('2027-01-01T00:00:00Z')",
			},
		},
	}

	second := Finding{
		ID:       "GCP001",
		Source:   "gcp",
		Category: "iam",
		Asset:    "project-a",
		Evidence: map[string]any{
			"role":    "roles/editor",
			"members": []string{"user:a@example.com", "user:b@example.com"},
			"condition": map[string]any{
				"expression": "request.time < timestamp('2027-01-01T00:00:00Z')",
			},
		},
	}

	if stableFingerprint(first) != stableFingerprint(second) {
		t.Fatal("member ordering should not change the fingerprint")
	}

	second.Evidence["members"] = []string{"user:a@example.com", "user:c@example.com"}
	if stableFingerprint(first) == stableFingerprint(second) {
		t.Fatal("different IAM members should produce different fingerprints")
	}
}

func TestStableFingerprintGCP003PublicPrincipals(t *testing.T) {
	first := Finding{
		ID:       "GCP003",
		Source:   "gcp",
		Category: "iam",
		Asset:    "project-a",
		Evidence: map[string]any{
			"role":              "roles/viewer",
			"public_principals": []string{"allUsers"},
			"binding_members":   []string{"allUsers", "user:a@example.com"},
		},
	}

	second := first
	second.Evidence = map[string]any{
		"role":              "roles/viewer",
		"public_principals": []string{"allUsers"},
		"binding_members":   []string{"allUsers", "user:b@example.com"},
	}

	if stableFingerprint(first) != stableFingerprint(second) {
		t.Fatal("unrelated private IAM members should not change the public exposure fingerprint")
	}

	second.Evidence["public_principals"] = []string{"allAuthenticatedUsers"}

	if stableFingerprint(first) == stableFingerprint(second) {
		t.Fatal("different public principals should produce different fingerprints")
	}
}

func TestStableFingerprintIncludesAssetAndKeyName(t *testing.T) {
	base := Finding{
		ID:       "AWS001",
		Source:   "aws",
		Category: "compute",
		Asset:    "instance-1",
	}

	otherAsset := base
	otherAsset.Asset = "instance-2"

	if stableFingerprint(base) == stableFingerprint(otherAsset) {
		t.Fatal("different assets should produce different fingerprints")
	}

	keyA := Finding{
		ID:       "GCP002",
		Source:   "gcp",
		Category: "iam",
		Asset:    "service-account@example.com",
		Evidence: map[string]any{"key_name": "key-a"},
	}
	keyB := keyA
	keyB.Evidence = map[string]any{"key_name": "key-b"}

	if stableFingerprint(keyA) == stableFingerprint(keyB) {
		t.Fatal("different service account keys should produce different fingerprints")
	}
}

func TestReportNormalizeSortsAndRecalculates(t *testing.T) {
	report := Report{
		OverallStatus: StatusPass,
		Summary: Summary{
			Passed: 99,
		},
		Findings: []Finding{
			{ID: "RULE2", Category: "test", Status: StatusCritical, Severity: "high"},
			{ID: "RULE1", Category: "test", Status: StatusWarning, Severity: "medium"},
		},
		Modules: []ModuleResult{
			{Name: "z-module", Status: ModuleCompleted},
			{Name: "a-module", Status: ModuleSkipped},
		},
		Coverage: []Coverage{
			{Provider: "z-provider", Category: "compute", Status: CoverageCompleted},
			{Provider: "a-provider", Category: "iam", Status: CoveragePartial},
		},
	}

	report.Normalize()

	if report.Summary.Passed != 0 ||
		report.Summary.Warnings != 1 ||
		report.Summary.Critical != 1 ||
		report.Summary.Errors != 0 {
		t.Fatalf("unexpected recalculated summary: %+v", report.Summary)
	}

	if report.OverallStatus != StatusCritical {
		t.Fatalf("expected overall critical, got %q", report.OverallStatus)
	}

	for _, finding := range report.Findings {
		if finding.Fingerprint == "" {
			t.Fatalf("finding %q has an empty fingerprint", finding.ID)
		}
		if finding.Source != "native" {
			t.Fatalf("expected default source native, got %q", finding.Source)
		}
	}

	if report.Modules[0].Name != "a-module" {
		t.Fatalf("modules are not sorted: %+v", report.Modules)
	}
	if report.Coverage[0].Provider != "a-provider" {
		t.Fatalf("coverage is not sorted: %+v", report.Coverage)
	}

	before := Report{
		GeneratedAt:   report.GeneratedAt,
		OverallStatus: report.OverallStatus,
		Summary:       report.Summary,
		Modules:       append([]ModuleResult(nil), report.Modules...),
		Coverage:      append([]Coverage(nil), report.Coverage...),
		Findings:      append([]Finding(nil), report.Findings...),
	}

	report.Normalize()

	if !reflect.DeepEqual(before, report) {
		t.Fatal("Normalize should be idempotent")
	}
}

func TestStableFingerprintAfterJSONRoundTrip(t *testing.T) {
	original := Finding{
		ID:       "GCP003",
		Source:   "gcp",
		Category: "iam",
		Asset:    "project-a",
		Evidence: map[string]any{
			"role": "roles/viewer",
			"binding_members": []string{
				"allUsers",
				"user:a@example.com",
			},
		},
	}

	before := stableFingerprint(original)

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}

	var decoded Finding
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}

	after := stableFingerprint(decoded)

	if before != after {
		t.Fatalf("fingerprint changed after JSON round trip: before=%s after=%s", before, after)
	}
}

func TestReportNormalizeSeverity(t *testing.T) {
	report := Report{
		Findings: []Finding{
			{ID: "LOW001", Severity: " HIGH "},
			{ID: "LOW002", Severity: " Medium "},
			{ID: "LOW003", Severity: " INFO "},
			{ID: "LOW004", Severity: " Custom-Risk "},
		},
	}

	report.Normalize()

	got := make(map[string]string)
	for _, finding := range report.Findings {
		got[finding.ID] = finding.Severity
	}

	expected := map[string]string{
		"LOW001": "high",
		"LOW002": "medium",
		"LOW003": "info",
		"LOW004": "custom-risk",
	}

	if !reflect.DeepEqual(got, expected) {
		t.Fatalf("unexpected normalized severities: got=%v want=%v", got, expected)
	}
}

func TestReportNormalizeDeduplicatesAndMergesEvidence(t *testing.T) {
	first := Finding{
		ID:       "APPSEC-VULN-TEST-123",
		Source:   "snyk",
		Category: "application",
		Asset:    "example.com/package@1.0.0",
		Status:   StatusWarning,
		Severity: "medium",
		Message:  "Example vulnerability",
		Evidence: map[string]any{
			"references": []string{"https://example.com/advisory"},
			"dependency_paths": [][]string{
				{"root", "package-a", "package-b"},
			},
		},
	}

	second := Finding{
		ID:       "APPSEC-VULN-TEST-123",
		Source:   "snyk",
		Category: "application",
		Asset:    "example.com/package@1.0.0",
		Status:   StatusCritical,
		Severity: "high",
		Message:  "Example vulnerability",
		Evidence: map[string]any{
			"references": []string{
				"https://example.com/advisory",
				"https://example.com/another-advisory",
			},
			"dependency_paths": [][]string{
				{"root", "package-c", "package-b"},
			},
		},
	}

	report := Report{
		Findings: []Finding{first, second},
	}

	report.Normalize()

	if len(report.Findings) != 1 {
		t.Fatalf("expected one deduplicated finding, got %d", len(report.Findings))
	}

	finding := report.Findings[0]

	if finding.Severity != "high" {
		t.Fatalf("expected highest severity high, got %q", finding.Severity)
	}

	if finding.Status != StatusCritical {
		t.Fatalf("expected critical status, got %q", finding.Status)
	}

	references := evidenceStrings(finding.Evidence["references"])
	if len(references) != 2 {
		t.Fatalf("expected two unique references, got %v", references)
	}

	rawPaths, ok := finding.Evidence["dependency_paths"].([][]string)
	if !ok {
		t.Fatalf("expected dependency_paths as [][]string, got %T",
			finding.Evidence["dependency_paths"])
	}

	if len(rawPaths) != 2 {
		t.Fatalf("expected two dependency paths, got %v", rawPaths)
	}

	expectedPaths := [][]string{
		{"root", "package-a", "package-b"},
		{"root", "package-c", "package-b"},
	}

	if !reflect.DeepEqual(rawPaths, expectedPaths) {
		t.Fatalf("dependency paths were not preserved: got=%v want=%v",
			rawPaths, expectedPaths)
	}

	if report.Summary.Critical != 1 || report.Summary.Warnings != 0 {
		t.Fatalf("unexpected summary after deduplication: %+v", report.Summary)
	}
}

func TestReportNormalizeKeepsDifferentAssetsSeparate(t *testing.T) {
	report := Report{
		Findings: []Finding{
			{
				ID:       "RULE001",
				Source:   "native",
				Category: "compute",
				Asset:    "instance-a",
				Status:   StatusWarning,
				Severity: "medium",
			},
			{
				ID:       "RULE001",
				Source:   "native",
				Category: "compute",
				Asset:    "instance-b",
				Status:   StatusWarning,
				Severity: "medium",
			},
		},
	}

	report.Normalize()

	if len(report.Findings) != 2 {
		t.Fatalf("different assets must remain separate; got %d findings",
			len(report.Findings))
	}

	if report.Findings[0].Fingerprint == report.Findings[1].Fingerprint {
		t.Fatal("different assets must have different fingerprints")
	}
}

func TestReportNormalizePreservesUnknownSeverity(t *testing.T) {
	report := Report{
		Findings: []Finding{
			{
				ID:       "CUSTOM001",
				Source:   "custom",
				Category: "test",
				Asset:    "asset-a",
				Status:   StatusWarning,
				Severity: " Vendor-Specific ",
			},
		},
	}

	report.Normalize()

	if len(report.Findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(report.Findings))
	}

	if report.Findings[0].Severity != "vendor-specific" {
		t.Fatalf("unknown severity was not preserved: %q",
			report.Findings[0].Severity)
	}
}

func TestReportNormalizeIsOrderIndependent(t *testing.T) {
	first := Finding{
		ID: "RULE001", Source: "scanner", Category: "application",
		Asset: "package-a@1.0", Status: StatusWarning,
		Severity: "medium", Message: "Finding from scanner B",
		Evidence: map[string]any{
			"detail":     "detail-b",
			"references": []string{"https://example.com/b"},
		},
	}
	second := Finding{
		ID: "RULE001", Source: "scanner", Category: "application",
		Asset: "package-a@1.0", Status: StatusCritical,
		Severity: "high", Message: "Finding from scanner A",
		Evidence: map[string]any{
			"detail":     "detail-a",
			"references": []string{"https://example.com/a"},
		},
	}

	forward := Report{Findings: []Finding{first, second}}
	reverse := Report{Findings: []Finding{second, first}}

	forward.Normalize()
	reverse.Normalize()

	if !reflect.DeepEqual(forward.Findings, reverse.Findings) {
		t.Fatalf("normalization depends on input order:\nforward=%+v\nreverse=%+v",
			forward.Findings, reverse.Findings)
	}
	if !reflect.DeepEqual(forward.Summary, reverse.Summary) {
		t.Fatalf("summary depends on input order: forward=%+v reverse=%+v",
			forward.Summary, reverse.Summary)
	}
	if forward.OverallStatus != reverse.OverallStatus {
		t.Fatalf("overall status depends on input order: forward=%q reverse=%q",
			forward.OverallStatus, reverse.OverallStatus)
	}
}

func TestReportNormalizeIsIdempotentWithConflicts(t *testing.T) {
	report := Report{
		Findings: []Finding{
			{
				ID: "RULE002", Source: "scanner", Category: "application",
				Asset: "package-b@1.0", Status: StatusWarning,
				Severity: "medium", Message: "Message B",
				Evidence: map[string]any{"detail": "value-b"},
			},
			{
				ID: "RULE002", Source: "scanner", Category: "application",
				Asset: "package-b@1.0", Status: StatusCritical,
				Severity: "high", Message: "Message A",
				Evidence: map[string]any{"detail": "value-a"},
			},
		},
	}

	report.Normalize()

	before, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}

	report.Normalize()

	after, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}

	if string(before) != string(after) {
		t.Fatalf("Normalize is not idempotent:\nbefore=%s\nafter=%s", before, after)
	}
}

func TestReportNormalizePreservesConflictsAfterJSONRoundTrip(t *testing.T) {
	report := Report{
		Findings: []Finding{
			{
				ID: "ROUNDTRIP001", Source: "scanner", Category: "application",
				Asset: "package-a@1.0", Status: StatusWarning,
				Severity: "medium", Message: "Message A",
				Evidence: map[string]any{"detail": "value-a"},
			},
			{
				ID: "ROUNDTRIP001", Source: "scanner", Category: "application",
				Asset: "package-a@1.0", Status: StatusCritical,
				Severity: "high", Message: "Message B",
				Evidence: map[string]any{"detail": "value-b"},
			},
		},
	}

	report.Normalize()

	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}

	var reloaded Report
	if err := json.Unmarshal(encoded, &reloaded); err != nil {
		t.Fatal(err)
	}

	reloaded.Findings = append(reloaded.Findings, Finding{
		ID: "ROUNDTRIP001", Source: "scanner", Category: "application",
		Asset: "package-a@1.0", Status: StatusCritical,
		Severity: "critical", Message: "Message C",
		Evidence: map[string]any{"detail": "value-c"},
	})

	reloaded.Normalize()

	if len(reloaded.Findings) != 1 {
		t.Fatalf("expected one deduplicated finding after JSON round trip, got %d",
			len(reloaded.Findings))
	}

	rawConflicts, ok := reloaded.Findings[0].Evidence["evidence_conflicts"]
	if !ok {
		t.Fatal("evidence_conflicts is missing after JSON round trip")
	}

	conflicts := evidenceConflictMap(rawConflicts)
	details := make(map[string]bool)
	for _, value := range conflicts["detail"] {
		details[stableJSON(value)] = true
	}

	for _, expected := range []string{"value-a", "value-b", "value-c"} {
		if !details[stableJSON(expected)] {
			t.Errorf("evidence conflict %q was lost; retained values: %#v",
				expected, conflicts["detail"])
		}
	}
}

func TestReportNormalizeKeepsNilEvidenceNil(t *testing.T) {
	report := Report{
		Findings: []Finding{
			{
				ID: "RULE003", Source: "scanner", Category: "compute",
				Asset: "instance-a", Status: StatusWarning, Severity: "low",
			},
			{
				ID: "RULE003", Source: "scanner", Category: "compute",
				Asset: "instance-a", Status: StatusWarning, Severity: "low",
			},
		},
	}

	report.Normalize()

	if len(report.Findings) != 1 {
		t.Fatalf("expected one deduplicated finding, got %d", len(report.Findings))
	}
	if report.Findings[0].Evidence != nil {
		t.Fatalf("expected nil evidence to remain nil, got %#v", report.Findings[0].Evidence)
	}
}
