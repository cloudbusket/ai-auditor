package checks

import (
	"testing"
	"time"
)

func TestGCP002ExplanationValidityWindow(t *testing.T) {
	now := time.Now().UTC()

	tests := []struct {
		name        string
		validAfter  string
		validBefore string
		want        bool
	}{
		{
			name: "no validity boundaries",
			want: true,
		},
		{
			name:        "currently valid",
			validAfter:  now.Add(-time.Hour).Format(time.RFC3339),
			validBefore: now.Add(time.Hour).Format(time.RFC3339),
			want:        true,
		},
		{
			name:        "expired",
			validAfter:  now.Add(-2 * time.Hour).Format(time.RFC3339),
			validBefore: now.Add(-time.Hour).Format(time.RFC3339),
			want:        false,
		},
		{
			name:       "not yet valid",
			validAfter: now.Add(time.Hour).Format(time.RFC3339),
			want:       false,
		},
		{
			name:       "malformed start",
			validAfter: "not-a-timestamp",
			want:       false,
		},
		{
			name:        "malformed end",
			validBefore: "not-a-timestamp",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			finding := Finding{
				ID:     "GCP002",
				Status: StatusWarning,
				Evidence: map[string]any{
					"key_name":          "test-key",
					"disabled":          false,
					"valid_after_time":  tt.validAfter,
					"valid_before_time": tt.validBefore,
				},
			}

			got := generatedExplanation(finding) != nil
			if got != tt.want {
				t.Fatalf("generatedExplanation() != nil = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestK8S007ExplanationRequiresServiceType(t *testing.T) {
	baseEvidence := map[string]any{
		"exposure_reasons": []string{"LoadBalancer"},
	}

	tests := []struct {
		name     string
		evidence map[string]any
		want     bool
	}{
		{
			name:     "missing service type",
			evidence: baseEvidence,
			want:     false,
		},
		{
			name: "service type present",
			evidence: map[string]any{
				"exposure_reasons": []string{"LoadBalancer"},
				"type":             "LoadBalancer",
			},
			want: true,
		},
		{
			name: "missing exposure reasons",
			evidence: map[string]any{
				"type": "LoadBalancer",
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			finding := Finding{
				ID:       "K8S007",
				Status:   StatusWarning,
				Evidence: tt.evidence,
			}

			got := generatedExplanation(finding) != nil
			if got != tt.want {
				t.Fatalf("generatedExplanation() != nil = %v, want %v", got, tt.want)
			}
		})
	}
}
