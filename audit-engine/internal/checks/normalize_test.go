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
