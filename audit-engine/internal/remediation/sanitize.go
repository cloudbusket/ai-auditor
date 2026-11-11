package remediation

import (
	"regexp"
	"strings"
	"unicode"

	"github.com/cloudbusket/ai-auditor/audit-engine/internal/checks"
)

var (
	privateKeyPattern = regexp.MustCompile(
		`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`,
	)

	bearerPattern = regexp.MustCompile(
		`(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+`,
	)

	secretAssignmentPattern = regexp.MustCompile(
		`(?i)((?:api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|password|passwd|secret|token|authorization)\s*[:=]\s*["']?)[^\s,"';]+`,
	)

	awsAccessKeyPattern = regexp.MustCompile(
		`\bAKIA[0-9A-Z]{16}\b`,
	)
)

const (
	maxFindingTextBytes = 4000
	maxContextBytes     = 4000
)

func sanitizeText(value string, maxBytes int) string {
	value = strings.ToValidUTF8(value, "")
	value = privateKeyPattern.ReplaceAllString(value, "[REDACTED PRIVATE KEY]")
	value = bearerPattern.ReplaceAllString(value, "Bearer [REDACTED]")
	value = secretAssignmentPattern.ReplaceAllString(value, "${1}[REDACTED]")
	value = awsAccessKeyPattern.ReplaceAllString(value, "[REDACTED AWS ACCESS KEY]")

	value = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			return -1
		}
		return r
	}, value)

	if len(value) > maxBytes {
		value = value[:maxBytes]
		value = strings.ToValidUTF8(value, "")
	}

	return strings.TrimSpace(value)
}

func sanitizeFinding(finding checks.Finding) checks.Finding {
	finding.ID = sanitizeText(finding.ID, 256)
	finding.Source = sanitizeText(finding.Source, 256)
	finding.Category = sanitizeText(finding.Category, 256)
	finding.Asset = sanitizeText(finding.Asset, 512)
	finding.Severity = sanitizeText(finding.Severity, 128)
	finding.Message = sanitizeText(finding.Message, maxFindingTextBytes)
	finding.Description = sanitizeText(finding.Description, maxFindingTextBytes)
	finding.Recommendation = sanitizeText(finding.Recommendation, maxFindingTextBytes)

	// Raw inventory evidence is deliberately excluded from AI requests.
	finding.Evidence = nil

	return finding
}

func sanitizeAdditionalContext(value string) string {
	return sanitizeText(value, maxContextBytes)
}
