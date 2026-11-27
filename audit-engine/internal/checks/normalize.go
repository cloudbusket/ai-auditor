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

func normalizeSeverity(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func severityRank(value string) (int, bool) {
	switch normalizeSeverity(value) {
	case "info":
		return 0, true
	case "low":
		return 1, true
	case "medium":
		return 2, true
	case "high":
		return 3, true
	case "critical":
		return 4, true
	default:
		return 0, false
	}
}

func mergeSeverity(a, b string) string {
	a = normalizeSeverity(a)
	b = normalizeSeverity(b)

	ar, aKnown := severityRank(a)
	br, bKnown := severityRank(b)

	// Preserve unsupported values so --fail-on continues to fail closed.
	if !aKnown || !bKnown {
		if !aKnown && !bKnown {
			if a < b {
				return a
			}
			return b
		}
		if !aKnown {
			return a
		}
		return b
	}

	if br > ar {
		return b
	}
	return a
}

func statusRank(status Status) int {
	switch status {
	case StatusPass:
		return 0
	case StatusWarning:
		return 1
	case StatusCritical:
		return 2
	case StatusError:
		return 3
	default:
		return -1
	}
}

func mergeUniqueStringsSorted(a, b []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(a)+len(b))

	for _, value := range append(append([]string(nil), a...), b...) {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}

	sort.Strings(result)
	return result
}

func mergeEvidenceValue(a, b any) (any, bool) {
	if stableJSON(a) == stableJSON(b) {
		return a, false
	}

	switch left := a.(type) {
	case []string:
		if right, ok := b.([]string); ok {
			return mergeUniqueStringsSorted(left, right), false
		}
	case [][]string:
		if right, ok := b.([][]string); ok {
			paths := make(map[string][]string)
			for _, path := range append(append([][]string(nil), left...), right...) {
				key := stableJSON(path)
				paths[key] = append([]string(nil), path...)
			}
			keys := make([]string, 0, len(paths))
			for key := range paths {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			result := make([][]string, 0, len(keys))
			for _, key := range keys {
				result = append(result, paths[key])
			}
			return result, false
		}
	case []any:
		if right, ok := b.([]any); ok {
			values := make(map[string]any)
			for _, value := range append(append([]any(nil), left...), right...) {
				values[stableJSON(value)] = value
			}
			keys := make([]string, 0, len(values))
			for key := range values {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			result := make([]any, 0, len(keys))
			for _, key := range keys {
				result = append(result, values[key])
			}
			return result, false
		}
	case map[string]any:
		if right, ok := b.(map[string]any); ok {
			return mergeEvidenceMaps(left, right), false
		}
	}

	return a, true
}

// evidenceConflictMap accepts both native and JSON-decoded conflict maps.
func evidenceConflictMap(value any) map[string][]any {
	result := make(map[string][]any)

	addValues := func(key string, raw any) {
		if key == "" || raw == nil {
			return
		}

		switch values := raw.(type) {
		case []any:
			result[key] = append(result[key], values...)
		case []string:
			for _, value := range values {
				result[key] = append(result[key], value)
			}
		default:
			result[key] = append(result[key], raw)
		}
	}

	switch conflicts := value.(type) {
	case map[string][]any:
		for key, values := range conflicts {
			addValues(key, values)
		}
	case map[string]any:
		for key, values := range conflicts {
			addValues(key, values)
		}
	}

	return result
}

func addEvidenceConflict(evidence map[string]any, key string, values ...any) {
	conflicts := evidenceConflictMap(evidence["evidence_conflicts"])
	if conflicts == nil {
		conflicts = make(map[string][]any)
	}

	byJSON := make(map[string]any)

	for _, value := range append(conflicts[key], values...) {
		byJSON[stableJSON(value)] = value
	}

	keys := make([]string, 0, len(byJSON))
	for value := range byJSON {
		keys = append(keys, value)
	}
	sort.Strings(keys)

	merged := make([]any, 0, len(keys))
	for _, value := range keys {
		merged = append(merged, byJSON[value])
	}

	conflicts[key] = merged
	evidence["evidence_conflicts"] = conflicts
}

func mergeEvidenceMaps(a, b map[string]any) map[string]any {
	if a == nil && b == nil {
		return nil
	}

	result := make(map[string]any, len(a)+len(b))

	for key, value := range a {
		result[key] = value
	}

	for key, incoming := range b {
		if key == "evidence_conflicts" {
			incomingConflicts := evidenceConflictMap(incoming)
			for conflictKey, values := range incomingConflicts {
				addEvidenceConflict(result, conflictKey, values...)
			}
			continue
		}

		current, exists := result[key]
		if !exists {
			result[key] = incoming
			continue
		}

		merged, conflict := mergeEvidenceValue(current, incoming)
		if conflict {
			addEvidenceConflict(result, key, current, incoming)

			// Choose a deterministic representative while retaining
			// both original values in evidence_conflicts.
			if stableJSON(incoming) < stableJSON(current) {
				result[key] = incoming
			}
		} else {
			result[key] = merged
		}
	}

	return result
}

func mergeFinding(a, b Finding) Finding {
	result := a

	result.Severity = mergeSeverity(a.Severity, b.Severity)
	if statusRank(b.Status) > statusRank(a.Status) {
		result.Status = b.Status
	}

	if result.Message == "" || (b.Message != "" && b.Message < result.Message) {
		if a.Message != "" && b.Message != "" && a.Message != b.Message {
			if result.Evidence == nil {
				result.Evidence = make(map[string]any)
			}
			addEvidenceConflict(result.Evidence, "message", a.Message, b.Message)
		}
		result.Message = b.Message
	} else if b.Message != "" && a.Message != b.Message {
		if result.Evidence == nil {
			result.Evidence = make(map[string]any)
		}
		addEvidenceConflict(result.Evidence, "message", a.Message, b.Message)
	}

	if result.Description == "" || (b.Description != "" && b.Description < result.Description) {
		if a.Description != "" && b.Description != "" && a.Description != b.Description {
			if result.Evidence == nil {
				result.Evidence = make(map[string]any)
			}
			addEvidenceConflict(result.Evidence, "description", a.Description, b.Description)
		}
		result.Description = b.Description
	} else if b.Description != "" && a.Description != b.Description {
		if result.Evidence == nil {
			result.Evidence = make(map[string]any)
		}
		addEvidenceConflict(result.Evidence, "description", a.Description, b.Description)
	}

	if result.Recommendation == "" || (b.Recommendation != "" && b.Recommendation < result.Recommendation) {
		if a.Recommendation != "" && b.Recommendation != "" && a.Recommendation != b.Recommendation {
			if result.Evidence == nil {
				result.Evidence = make(map[string]any)
			}
			addEvidenceConflict(result.Evidence, "recommendation", a.Recommendation, b.Recommendation)
		}
		result.Recommendation = b.Recommendation
	} else if b.Recommendation != "" && a.Recommendation != b.Recommendation {
		if result.Evidence == nil {
			result.Evidence = make(map[string]any)
		}
		addEvidenceConflict(result.Evidence, "recommendation", a.Recommendation, b.Recommendation)
	}

	result.Evidence = mergeEvidenceMaps(result.Evidence, b.Evidence)
	return result
}

// Normalize generates stable finding fingerprints, sorts report collections,
// and recalculates summary/status from the final findings.
func (r *Report) Normalize() {
	if r == nil {
		return
	}

	// Normalize fields and calculate fingerprints before deduplication.
	for i := range r.Findings {
		if strings.TrimSpace(r.Findings[i].Source) == "" {
			r.Findings[i].Source = "native"
		} else {
			r.Findings[i].Source = strings.TrimSpace(r.Findings[i].Source)
		}
		r.Findings[i].Severity = normalizeSeverity(r.Findings[i].Severity)
		r.Findings[i].Fingerprint = stableFingerprint(r.Findings[i])
	}

	// Group only identical finding identities. Distinct assets, rules,
	// categories, and sources remain separate.
	byFingerprint := make(map[string]Finding, len(r.Findings))
	fingerprints := make([]string, 0, len(r.Findings))

	for _, finding := range r.Findings {
		existing, exists := byFingerprint[finding.Fingerprint]
		if !exists {
			byFingerprint[finding.Fingerprint] = finding
			fingerprints = append(fingerprints, finding.Fingerprint)
			continue
		}
		byFingerprint[finding.Fingerprint] = mergeFinding(existing, finding)
	}

	r.Findings = make([]Finding, 0, len(fingerprints))
	for _, fingerprint := range fingerprints {
		finding := byFingerprint[fingerprint]
		finding.Fingerprint = fingerprint
		r.Findings = append(r.Findings, finding)
	}

	// Calculate risk after deduplication and merging.
	for i := range r.Findings {
		applyRisk(&r.Findings[i])
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
