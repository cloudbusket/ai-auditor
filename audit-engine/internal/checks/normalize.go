package checks

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
)

type findingIdentity struct {
	Source    string   `json:"source"`
	Category  string   `json:"category"`
	RuleID    string   `json:"rule_id"`
	Asset     string   `json:"asset"`
	Role      string   `json:"role,omitempty"`
	Members   []string `json:"members,omitempty"`
	Condition any      `json:"condition,omitempty"`
	KeyName   string   `json:"key_name,omitempty"`
}

func evidenceStrings(value any) []string {
	switch values := value.(type) {
	case []string:
		return append([]string(nil), values...)
	case []any:
		result := make([]string, 0, len(values))
		for _, value := range values {
			if item, ok := value.(string); ok {
				result = append(result, item)
			}
		}
		return result
	default:
		return nil
	}
}

// stableFingerprint creates an identity for a finding instance without
// including mutable measurements, timestamps, messages, or recommendations.
func stableFingerprint(f Finding) string {
	identity := findingIdentity{
		Source:   strings.TrimSpace(f.Source),
		Category: strings.TrimSpace(f.Category),
		RuleID:   strings.TrimSpace(f.ID),
		Asset:    strings.TrimSpace(f.Asset),
	}

	switch f.ID {
	case "GCP001", "GCP003":
		identity.Role, _ = f.Evidence["role"].(string)

		members := evidenceStrings(f.Evidence["members"])
		if f.ID == "GCP003" {
			members = evidenceStrings(f.Evidence["public_principals"])
		}

		identity.Members = append([]string(nil), members...)
		sort.Strings(identity.Members)

		identity.Condition = f.Evidence["condition"]

	case "GCP002":
		identity.KeyName, _ = f.Evidence["key_name"].(string)
		if identity.KeyName == "" {
			identity.KeyName = f.Asset
		}
	}

	data, err := json.Marshal(identity)
	if err != nil {
		// The identity contains only JSON-compatible values from the report.
		// This fallback still produces a stable, non-empty identifier.
		data = []byte(identity.Source + "|" + identity.Category + "|" +
			identity.RuleID + "|" + identity.Asset)
	}

	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func stableJSON(v any) string {
	data, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(data)
}

// Normalize generates stable finding fingerprints, sorts report collections,
// and recalculates summary/status from the final findings.
func (r *Report) Normalize() {
	if r == nil {
		return
	}

	for i := range r.Findings {
		if r.Findings[i].Source == "" {
			r.Findings[i].Source = "native"
		}
		r.Findings[i].Fingerprint = stableFingerprint(r.Findings[i])
	}

	sort.Slice(r.Findings, func(i, j int) bool {
		a, b := r.Findings[i], r.Findings[j]
		if a.Fingerprint != b.Fingerprint {
			return a.Fingerprint < b.Fingerprint
		}
		return stableJSON(a) < stableJSON(b)
	})

	sort.Slice(r.Modules, func(i, j int) bool {
		a, b := r.Modules[i], r.Modules[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return stableJSON(a) < stableJSON(b)
	})

	sort.Slice(r.Coverage, func(i, j int) bool {
		a, b := r.Coverage[i], r.Coverage[j]
		if a.Provider != b.Provider {
			return a.Provider < b.Provider
		}
		if a.Category != b.Category {
			return a.Category < b.Category
		}
		return stableJSON(a) < stableJSON(b)
	})

	r.Summary = Summary{}
	r.OverallStatus = StatusPass

	for _, f := range r.Findings {
		switch f.Status {
		case StatusPass:
			r.Summary.Passed++
		case StatusWarning:
			r.Summary.Warnings++
		case StatusCritical:
			r.Summary.Critical++
		case StatusError:
			r.Summary.Errors++
		}

		switch f.Status {
		case StatusError:
			r.OverallStatus = StatusError
		case StatusCritical:
			if r.OverallStatus != StatusError {
				r.OverallStatus = StatusCritical
			}
		case StatusWarning:
			if r.OverallStatus == StatusPass {
				r.OverallStatus = StatusWarning
			}
		}
	}
}
