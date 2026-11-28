package dashboard

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/cloudbusket/ai-auditor/audit-engine/internal/appsec"
	"github.com/cloudbusket/ai-auditor/audit-engine/internal/audit"
	"github.com/cloudbusket/ai-auditor/audit-engine/internal/checks"
	"github.com/cloudbusket/ai-auditor/audit-engine/internal/cloud"
	"github.com/cloudbusket/ai-auditor/audit-engine/internal/inventory"
	"github.com/cloudbusket/ai-auditor/audit-engine/internal/remediation"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
)

// NewHandler creates the authenticated dashboard HTTP handler.
func NewHandler(password string) (http.Handler, error) {
	if password == "" {
		return nil, errors.New("dashboard password is required")
	}

	history, err := NewHistoryStore(os.Getenv("AUDITOR_HISTORY_DIR"))
	if err != nil {
		return nil, err
	}

	targetPath := strings.TrimSpace(os.Getenv("AUDITOR_SCAN_TARGET"))
	if targetPath == "" {
		targetPath = "."
	}

	cloudProjectID := strings.TrimSpace(os.Getenv("AUDITOR_GCP_PROJECT_ID"))

	mux := http.NewServeMux()
	// Initialize AI remediation components.
	credentials := remediation.NewMemoryCredentialStore()

	openAIProvider := remediation.NewOpenAIProvider(
		credentials,
		"",
		nil,
	)

	remediationService := remediation.NewService(
		openAIProvider,
		60*time.Second,
	)
	// Existing dashboard routes.
	mux.HandleFunc("/", dashboardPage)
	mux.HandleFunc("/api/overview", overviewHandler)
	mux.HandleFunc("/api/metrics", metricsHandler)
	mux.HandleFunc("/api/checks", checksHandler)

	// AI provider settings.
	mux.HandleFunc(
		"/api/settings/ai-provider",
		providerSettingsHandler(credentials),
	)

	mux.HandleFunc("/api/scan", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if !sameOriginRequest(r) {
			http.Error(w, "Cross-origin request rejected", http.StatusForbidden)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 6*time.Minute)
		defer cancel()

		scanner := &appsec.SnykScanner{}

		var cloudCollector cloud.Collector
		if cloudProjectID != "" {
			collector, err := cloud.NewGCPCollector(ctx)
			if err == nil {
				cloudCollector = collector
			}
		}

		report := audit.Run(ctx, scanner, audit.Config{
			TargetPath:     targetPath,
			Timeout:        5 * time.Minute,
			CloudCollector: cloudCollector,
			CloudConfig: cloud.Config{
				ProjectID: cloudProjectID,
			},
		})

		record, err := history.Save(report)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{
				"error": "Unable to save scan history",
			})
			return
		}

		writeJSON(w, http.StatusCreated, record)
	})

	mux.HandleFunc("/api/history", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		summaries, err := history.List()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{
				"error": "Unable to read scan history",
			})
			return
		}

		writeJSON(w, http.StatusOK, summaries)
	})
	mux.HandleFunc("/api/history/", func(w http.ResponseWriter, r *http.Request) {
		// AI remediation endpoint:
		// POST /api/history/{scanID}/findings/{findingID}/remediation
		if strings.Contains(r.URL.Path, "/findings/") {
			findingRemediationHandler(
				history,
				remediationService,
			)(w, r)
			return
		}

		// Existing scan-history endpoint:
		// GET /api/history/{scanID}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		id := strings.TrimPrefix(r.URL.Path, "/api/history/")
		if id == "" || strings.Contains(id, "/") {
			http.NotFound(w, r)
			return
		}

		record, err := history.Get(id)
		if errors.Is(err, os.ErrNotExist) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			http.Error(w, "Invalid scan history request", http.StatusBadRequest)
			return
		}

		writeJSON(w, http.StatusOK, record)
	})

	return authenticate(password, mux), nil
}

// sameOriginRequest rejects cross-origin requests when browser origin
// information is supplied. Non-browser clients without Origin are allowed.
func sameOriginRequest(r *http.Request) bool {
	if strings.EqualFold(r.Header.Get("Sec-Fetch-Site"), "cross-site") {
		return false
	}

	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}

	return origin == requestOrigin(r)
}

func requestOrigin(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	} else if strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		scheme = "https"
	}

	return scheme + "://" + r.Host
}

// authenticate protects the dashboard and all API endpoints.
func authenticate(password string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, suppliedPassword, ok := r.BasicAuth()

		validUser := subtle.ConstantTimeCompare(
			[]byte(username),
			[]byte("auditor"),
		)

		validPassword := subtle.ConstantTimeCompare(
			[]byte(suppliedPassword),
			[]byte(password),
		)

		if !ok || validUser != 1 || validPassword != 1 {
			w.Header().Set(
				"WWW-Authenticate",
				`Basic realm="CloudBusket AI Auditor"`,
			)
			http.Error(w, "Authentication required", http.StatusUnauthorized)
			return
		}

		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")

		next.ServeHTTP(w, r)
	})
}

// dashboardPage serves the browser dashboard.
func dashboardPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(indexHTML))
}

// overviewHandler returns the actual server inventory and health checks.
func overviewHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	inv, err := inventory.Collect()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "Unable to collect infrastructure inventory",
		})
		return
	}

	report := checks.RunHostChecks()

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"inventory": inv,
		"checks":    report,
	})
}

// metricsHandler returns live CPU and memory utilization.
func metricsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cpuValues, err := cpu.Percent(500*time.Millisecond, false)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "Unable to collect CPU metrics",
		})
		return
	}

	vm, err := mem.VirtualMemory()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "Unable to collect memory metrics",
		})
		return
	}

	var cpuPercent float64
	if len(cpuValues) > 0 {
		cpuPercent = cpuValues[0]
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"cpu_percent":     cpuPercent,
		"memory_total_gb": float64(vm.Total) / (1024 * 1024 * 1024),
		"memory_used_gb":  float64(vm.Used) / (1024 * 1024 * 1024),
		"memory_percent":  vm.UsedPercent,
		"collected_at":    time.Now().UTC().Format(time.RFC3339),
	})
}

// checksHandler returns infrastructure security and health findings.
func checksHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	report := checks.RunHostChecks()
	report.Normalize()
	writeJSON(w, http.StatusOK, report)
}

// writeJSON sends a JSON response.
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

// Dashboard HTML.
const indexHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CloudBusket AI Auditor</title>

<style>
:root {
    color-scheme: dark;
    --background: #0b1220;
    --panel: #141f32;
    --border: #26364d;
    --text: #e7edf7;
    --muted: #91a1b8;
    --green: #4caf50;
}

* {
    box-sizing: border-box;
}

body {
    margin: 0;
    padding: 28px;
    background: var(--background);
    color: var(--text);
    font-family: Arial, sans-serif;
}

header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 15px;
    margin-bottom: 25px;
}

h1 {
    margin: 0;
    font-size: 25px;
}

h2 {
    font-size: 18px;
    margin-top: 0;
}

.panel {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 20px;
    margin-bottom: 16px;
    overflow-x: auto;
}

.grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
    gap: 16px;
}

.muted {
    color: var(--muted);
}

.metric {
    font-size: 30px;
    font-weight: bold;
    margin: 10px 0;
}

#hostname {
    font-size: clamp(18px, 2vw, 25px);
    overflow-wrap: anywhere;
    word-break: normal;
    line-height: 1.25;
}

.skipped {
    color: var(--muted);
}

.bar {
    height: 8px;
    background: #26364d;
    border-radius: 10px;
    overflow: hidden;
}

.bar span {
    display: block;
    height: 100%;
    background: var(--green);
    width: 0;
}

button {
    background: var(--green);
    color: #07140a;
    border: none;
    padding: 10px 15px;
    border-radius: 7px;
    font-weight: bold;
    cursor: pointer;
}

button:disabled {
    opacity: .55;
    cursor: not-allowed;
}

.secondary {
    background: #26364d;
    color: var(--text);
}

table {
    width: 100%;
    border-collapse: collapse;
    min-width: 520px;
}

.finding-filters {
    display: flex;
    flex-wrap: wrap;
    align-items: end;
    gap: 12px;
    margin: 14px 0;
    padding: 14px;
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 8px;
}

.finding-filter {
    display: flex;
    flex-direction: column;
    gap: 6px;
    min-width: 150px;
}

.finding-filter label {
    color: var(--muted);
    font-size: 12px;
}

.finding-filter select {
    min-width: 150px;
    padding: 9px;
    border: 1px solid var(--border);
    border-radius: 6px;
    background: #0b1220;
    color: var(--text);
}

.finding-filter-count {
    color: var(--muted);
    font-size: 13px;
    margin: 10px 0;
}

th, td {
    padding: 10px;
    text-align: left;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
}

th {
    color: var(--muted);
}

.finding-details {
    min-width: 125px;
}

.finding-details summary {
    color: var(--green);
    cursor: pointer;
    font-weight: bold;
    padding: 5px 0;
}

.finding-details summary:focus-visible {
    outline: 2px solid var(--green);
    outline-offset: 4px;
    border-radius: 3px;
}

.finding-detail-content {
    min-width: 260px;
    max-width: 620px;
    padding: 12px;
    margin-top: 10px;
    border: 1px solid var(--border);
    border-radius: 8px;
    background: #0b1220;
    white-space: normal;
    overflow-wrap: anywhere;
}

.finding-detail-content section + section {
    border-top: 1px solid var(--border);
    margin-top: 12px;
    padding-top: 8px;
}

.finding-detail-content h4 {
    margin: 4px 0 8px;
    color: var(--muted);
}

.finding-detail-content p {
    line-height: 1.5;
    margin: 6px 0;
}

.evidence-list {
    margin: 6px 0;
    padding-left: 20px;
}

dl.evidence-list {
    padding: 0;
}

.evidence-entry {
    margin: 8px 0;
}

.evidence-entry dt {
    color: var(--muted);
    font-weight: bold;
    margin-bottom: 3px;
}

.evidence-entry dd {
    margin: 0 0 0 10px;
}

.evidence-value {
    white-space: pre-wrap;
    overflow-wrap: anywhere;
}

@media(max-width: 600px) {
    .finding-detail-content {
        min-width: 220px;
        max-width: 75vw;
    }
}

.pass {
    color: #7bd88f;
}

.warning {
    color: #f5c66a;
}

.critical, .error {
    color: #ff7777;
}

.status {
    text-transform: uppercase;
    font-weight: bold;
}

.history-row {
    cursor: pointer;
}

.history-row:hover {
    background: #1c2b42;
}

.notice {
    color: var(--muted);
    margin-top: 12px;
}

.ai-settings {
    display: grid;
    grid-template-columns: minmax(0, 1fr) auto;
    gap: 12px;
    align-items: end;
}

.ai-settings input,
.ai-settings textarea {
    width: 100%;
    padding: 11px;
    border: 1px solid var(--border);
    border-radius: 7px;
    background: #0b1220;
    color: var(--text);
}

.ai-settings label {
    display: block;
    margin-bottom: 7px;
    color: var(--muted);
}

.ai-actions {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    margin-top: 12px;
}

.remediation-card {
    border: 1px solid var(--border);
    border-radius: 9px;
    padding: 16px;
    margin: 14px 0;
    overflow-wrap: anywhere;
}

.remediation-card pre {
    white-space: pre-wrap;
    overflow-wrap: anywhere;
    background: #0b1220;
    padding: 12px;
    border-radius: 7px;
}

.remediation-card li {
    margin: 8px 0;
}

.remediation-status {
    margin-top: 10px;
    color: var(--muted);
}

@media(max-width: 600px) {
    .ai-settings {
        grid-template-columns: 1fr;
    }
}

@media(max-width: 600px) {
    body {
        padding: 15px;
    }
}

.risk-overview {
    margin: 16px 0 22px;
    padding: 16px;
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
}
.risk-overview h3 {
    margin: 0 0 14px;
}
.risk-count-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(125px, 1fr));
    gap: 10px;
    margin-bottom: 12px;
}
.risk-metric, .risk-count-card {
    padding: 12px;
    background: var(--background);
    border: 1px solid var(--border);
    border-radius: 8px;
}
.risk-metric span, .risk-count-card span,
.risk-metric small {
    display: block;
    color: var(--muted);
    font-size: 12px;
}
.risk-metric strong {
    display: block;
    margin: 6px 0;
    font-size: 23px;
}
.risk-count-card strong {
    display: block;
    margin-top: 5px;
    font-size: 20px;
}
.risk-top-list {
    padding-left: 22px;
}
.risk-top-list li {
    margin: 9px 0;
}
.risk-top-list li span {
    display: block;
    color: var(--muted);
    font-size: 12px;
    margin-top: 3px;
}

</style>
</head>

<body>

<header>
    <div>
        <h1>CloudBusket AI Auditor</h1>
        <div class="muted">Infrastructure Security & Health Dashboard</div>
    </div>

    <div>
        <span id="status">Connecting...</span>
        <button id="scanButton" onclick="runScan()">Run Assessment</button>
        <button class="secondary" onclick="refreshAll()">Refresh</button>
    </div>
</header>

<div id="scanMessage" class="notice"></div>

<section class="panel">
    <h2>AI Remediation Provider</h2>
    <p class="muted">
        Configure your OpenAI API key to generate advisory remediation plans.
        The key is held in server memory and is not stored in this browser.
    </p>

    <div id="aiProviderStatus" class="notice">
        Checking provider configuration...
    </div>

    <div class="ai-settings">
        <div>
            <label for="aiAPIKey">OpenAI API key</label>
            <input
                id="aiAPIKey"
                type="password"
                autocomplete="new-password"
                placeholder="Enter API key"
            >
        </div>

        <div class="ai-actions">
            <button id="saveAIKeyButton" type="button"
                onclick="saveAIProvider()">Save key</button>
            <button class="secondary" type="button"
                onclick="removeAIProvider()">Remove key</button>
        </div>
    </div>

    <div id="aiProviderMessage" class="remediation-status"></div>
</section>

<div class="grid">

    <section class="panel">
        <div class="muted">Hostname</div>
        <div class="metric" id="hostname">--</div>
        <div id="os" class="muted">Loading...</div>
    </section>

    <section class="panel">
        <div class="muted">CPU Utilization</div>
        <div class="metric" id="cpu">--</div>
        <div class="bar"><span id="cpuBar"></span></div>
    </section>

    <section class="panel">
        <div class="muted">Memory Utilization</div>
        <div class="metric" id="memory">--</div>
        <div class="bar"><span id="memoryBar"></span></div>
        <div id="memoryDetail" class="muted"></div>
    </section>

    <section class="panel">
        <div class="muted">Total Checks</div>
        <div class="metric" id="totalChecks">--</div>
        <div class="muted">Latest saved assessment</div>
    </section>

    <section class="panel">
        <div class="muted">Passed</div>
        <div class="metric pass" id="passedChecks">--</div>
    </section>

    <section class="panel">
        <div class="muted">Warnings</div>
        <div class="metric warning" id="warningChecks">--</div>
    </section>

    <section class="panel">
        <div class="muted">Critical</div>
        <div class="metric critical" id="criticalChecks">--</div>
    </section>

    <section class="panel">
        <div class="muted">Errors</div>
        <div class="metric error" id="errorChecks">--</div>
    </section>

</div>
<section class="panel">
    <h2>Latest Assessment</h2>
    <div id="latestAssessment" class="muted">No assessment loaded.</div>
    <div id="moduleResults"></div>
    <div id="coverageResults"></div>
</section>

<section class="panel">
    <h2>Scan History</h2>
    <div id="history">Loading scan history...</div>
</section>

<section class="panel">
    <h2>Selected Scan Details</h2>
    <div id="historyDetail" class="muted">Select a scan from history.</div>
</section>

<section class="panel">
    <h2>Cloud Inventory</h2>
    <div id="cloudInventory" class="muted">
        Select a scan to view its cloud inventory.
    </div>
</section>

<section class="panel">
    <h2>AI Remediation Results</h2>
    <div id="remediationResults" class="muted">
        Select a finding from a saved scan to generate a remediation plan.
    </div>
</section>

<section class="panel">
    <h2>Host Inventory</h2>
    <div id="hostDetails">Loading...</div>
</section>

<section class="panel">
    <h2>Disk Usage</h2>
    <div id="disks">Loading...</div>
</section>

<section class="panel">
    <h2>Services</h2>
    <div id="services">Loading...</div>
</section>

<section class="panel">
    <h2>Docker</h2>
    <div id="docker">Loading...</div>
</section>

<section class="panel">
    <h2>Security and Health Checks</h2>
    <div id="checks">Loading...</div>
</section>

<script>
async function getJSON(url, options) {
    const response = await fetch(url, {
        cache: "no-store",
        ...options
    });

    if (!response.ok) {
        throw new Error("HTTP " + response.status);
    }

    return response.json();
}

function safe(value) {
    return String(value ?? "").replace(/[&<>"']/g, function(c) {
        return {
            "&": "&amp;",
            "<": "&lt;",
            ">": "&gt;",
            '"': "&quot;",
            "'": "&#39;"
        }[c];
    });
}

function setBar(id, value) {
    const percentage = Math.max(0, Math.min(100, Number(value) || 0));
    document.getElementById(id).style.width = percentage + "%";
}

function statusClass(value) {
    return String(value || "").toLowerCase().replace(/[^a-z]/g, "");
}

function renderTable(headers, rows) {
    if (!rows.length) {
        return "<p class='muted'>No data available.</p>";
    }

    let html = "<table><thead><tr>";

    headers.forEach(function(header) {
        html += "<th>" + safe(header) + "</th>";
    });

    html += "</tr></thead><tbody>";

    rows.forEach(function(row) {
        html += "<tr>";

        row.forEach(function(value) {
            html += "<td>" + safe(value) + "</td>";
        });

        html += "</tr>";
    });

    html += "</tbody></table>";

    return html;
}

function isSensitiveEvidenceKey(key) {
    return /password|passwd|secret|token|credential|private.?key|api.?key|access.?key|authorization|cookie|client.?secret/i.test(
        String(key || "")
    );
}

function renderEvidenceValue(value, depth) {
    depth = depth || 0;

    if (value === null || value === undefined) {
        return "<span class='muted'>Not available</span>";
    }

    if (depth >= 5) {
        return "<span class='muted'>Nested evidence omitted (depth limit).</span>";
    }

    if (Array.isArray(value)) {
        if (value.length === 0) {
            return "<span class='muted'>Empty</span>";
        }

        return "<ul class='evidence-list'>" +
            value.map(function(item) {
                return "<li>" + renderEvidenceValue(item, depth + 1) + "</li>";
            }).join("") +
            "</ul>";
    }

    if (typeof value === "object") {
        const keys = Object.keys(value);

        if (keys.length === 0) {
            return "<span class='muted'>Empty</span>";
        }

        return "<dl class='evidence-list'>" +
            keys.map(function(key) {
                const label = safe(key);

                const rendered = isSensitiveEvidenceKey(key)
                    ? "<span class='muted'>[REDACTED]</span>"
                    : renderEvidenceValue(value[key], depth + 1);

                return "<div class='evidence-entry'>" +
                    "<dt>" + label + "</dt>" +
                    "<dd>" + rendered + "</dd>" +
                    "</div>";
            }).join("") +
            "</dl>";
    }

    let text = String(value);

    if (text.length > 4000) {
        text = text.slice(0, 4000) + " … [truncated]";
    }

    return "<span class='evidence-value'>" + safe(text) + "</span>";
}

function renderFindingExplanation(explanation) {
    if (!explanation || typeof explanation !== "object") {
        return "";
    }

    const fields = [
        ["Technical explanation", explanation.technical_explanation],
        ["Business impact", explanation.business_impact],
        ["Remediation rationale", explanation.remediation_rationale]
    ];

    const content = fields
        .filter(function (field) {
            return typeof field[1] === "string" && field[1].trim() !== "";
        })
        .map(function (field) {
            return "<p><strong>" + field[0] + ":</strong> " +
                safe(field[1]) + "</p>";
        })
        .join("");

    const confidenceLabels = {
        evidence_backed: "Evidence-backed",
        potential: "Potential",
        undetermined: "Undetermined"
    };

    const confidenceKey = String(
        explanation.impact_confidence || "undetermined"
    ).toLowerCase();

    const confidence = confidenceLabels[confidenceKey] || "Undetermined";

    const confidenceHTML =
        "<p><strong>Impact confidence:</strong> " +
        safe(confidence) + "</p>";

    const whyItMatters = typeof explanation.why_it_matters === "string" &&
        explanation.why_it_matters.trim() !== ""
        ? "<p>" + safe(explanation.why_it_matters) + "</p>"
        : "";

    if (!content && !whyItMatters) {
        return "";
    }

    return "<section class='finding-explanation'>" +
        "<h4>Why this matters</h4>" +
        whyItMatters +
        content +
        confidenceHTML +
        "</section>";
}

function renderFindingDetails(finding) {
    const description = finding.description
        ? "<p>" + safe(finding.description) + "</p>"
        : "<p class='muted'>No additional explanation was recorded for this finding.</p>";

    const evidence = finding.evidence &&
        typeof finding.evidence === "object" &&
        Object.keys(finding.evidence).length > 0
        ? renderEvidenceValue(finding.evidence, 0)
        : "<p class='muted'>No technical evidence was recorded.</p>";

    const recommendation = finding.recommendation
        ? "<p>" + safe(finding.recommendation) + "</p>"
        : "<p class='muted'>No recommendation was provided.</p>";

    const score = finding.risk_score == null ||
        !Number.isFinite(Number(finding.risk_score))
        ? "Not scored"
        : safe(String(finding.risk_score) + "/100");

    const bandLabels = {
        critical: "Critical",
        very_high: "Very High",
        moderate: "Moderate",
        low: "Low",
        informational: "Informational",
        unclassified: "Unclassified"
    };

    const priorityLabels = {
        immediate: "Immediate",
        urgent: "Urgent",
        planned: "Planned",
        routine: "Routine",
        manual_review: "Manual Review"
    };

    const bandKey = String(finding.risk_band || "unclassified").toLowerCase();
    const priorityKey = String(finding.risk_priority || "manual_review").toLowerCase();

    const band = safe(bandLabels[bandKey] || "Unclassified");
    const priority = safe(priorityLabels[priorityKey] || "Manual Review");
    const severity = safe(finding.severity || "Not recorded");

    const responseGuidance = {
        immediate: "Prioritize prompt review and remediation.",
        urgent: "Review and plan remediation as a high priority.",
        planned: "Include this finding in planned remediation work.",
        routine: "Address through routine maintenance and review.",
        manual_review: "Review manually; standard risk classification is unavailable."
    };

    const guidance = safe(
        responseGuidance[priorityKey] || responseGuidance.manual_review
    );

    const riskContext =
        "<section class='risk-context'>" +
            "<h4>Risk Context</h4>" +
            "<p><strong>Risk score:</strong> " + score + "</p>" +
            "<p><strong>Risk band:</strong> " + band + "</p>" +
            "<p><strong>Priority:</strong> " + priority + "</p>" +
            "<p><strong>Severity:</strong> " + severity + "</p>" +
            "<p><strong>Response guidance:</strong> " + guidance + "</p>" +
        "</section>";

    const explanation = renderFindingExplanation(finding.explanation);

    return "<details class='finding-details'>" +
        "<summary>View Details</summary>" +
        "<div class='finding-detail-content'>" +
            riskContext +
            explanation +
            "<section>" +
                "<h4>What happened?</h4>" +
                description +
            "</section>" +
            "<section>" +
                "<h4>Affected asset</h4>" +
                "<p>" + safe(finding.asset || "Not identified") + "</p>" +
            "</section>" +
            "<section>" +
                "<h4>Technical evidence</h4>" +
                evidence +
            "</section>" +
            "<section>" +
                "<h4>Recommended action</h4>" +
                recommendation +
            "</section>" +
        "</div>" +
        "</details>";
}

function renderRiskOverview(findings) {
    const bands = {
        critical: 0,
        very_high: 0,
        moderate: 0,
        low: 0,
        informational: 0,
        unclassified: 0
    };

    const classified = [];

    findings.forEach(function(f) {
        const band = String(f.risk_band || "").toLowerCase();
        const score = Number(f.risk_score);

        if (f.risk_score == null || !Number.isFinite(score) ||
            !Object.prototype.hasOwnProperty.call(bands, band) ||
            band === "unclassified") {
            bands.unclassified++;
            return;
        }

        bands[band]++;
        classified.push({finding: f, score: score});
    });

    classified.sort(function(a, b) {
        return b.score - a.score;
    });

    const maximum = classified.length ? classified[0] : null;

    let html = "<div class='risk-overview'>" +
        "<h3>Finding Risk Overview</h3>" +
        "<div class='risk-count-grid'>" +
        "<div class='risk-metric'><span>Maximum Finding Risk</span><strong>" +
        (maximum ? safe(maximum.score) + " / 100" : "--") +
        "</strong><small>" +
        (maximum ? safe(maximum.finding.risk_band) : "No classified findings") +
        "</small></div>" +
        "<div class='risk-metric'><span>Total Findings</span><strong>" +
        safe(findings.length) + "</strong></div>" +
        "<div class='risk-metric'><span>Classified Findings</span><strong>" +
        safe(classified.length) + "</strong></div>" +
        "<div class='risk-metric'><span>Unclassified</span><strong>" +
        safe(bands.unclassified) + "</strong></div>" +
        "</div>" +
        "<div class='risk-count-grid'>" +
        "<div class='risk-count-card'><span>Critical</span><strong>" +
        safe(bands.critical) + "</strong></div>" +
        "<div class='risk-count-card'><span>Very High</span><strong>" +
        safe(bands.very_high) + "</strong></div>" +
        "<div class='risk-count-card'><span>Moderate</span><strong>" +
        safe(bands.moderate) + "</strong></div>" +
        "<div class='risk-count-card'><span>Low</span><strong>" +
        safe(bands.low) + "</strong></div>" +
        "<div class='risk-count-card'><span>Informational</span><strong>" +
        safe(bands.informational) + "</strong></div>" +
        "</div>";

    if (classified.length > 0) {
        html += "<h4>Highest-Risk Findings</h4><ol class='risk-top-list'>";

        classified.slice(0, 5).forEach(function(item) {
            const f = item.finding;
            html += "<li><strong>" + safe(item.score) + " / 100</strong> — " +
                safe(f.asset || f.message || f.id || "Unnamed finding") +
                "<span>" + safe(f.risk_band) + " · " +
                safe(f.risk_priority || "Priority unavailable") +
                "</span></li>";
        });

        html += "</ol>";
    }

    return html + "</div>";
}

function renderFindings(findings, allowRemediation) {
    findings = Array.isArray(findings) ? findings : [];

    let html = renderRiskOverview(findings);

    if (findings.length === 0) {
        return html + "<p class='muted'>No findings.</p>";
    }

    const validBands = [
        "critical", "very_high", "moderate",
        "low", "informational"
    ];

    const validPriorities = [
        "immediate", "urgent", "planned", "routine"
    ];

    // Sort a copy so the original report order is not modified.
    const sortedFindings = findings.slice().sort(function(a, b) {
        const scoreA = a.risk_score == null
            ? -1 : Number(a.risk_score);
        const scoreB = b.risk_score == null
            ? -1 : Number(b.risk_score);

        const validA = Number.isFinite(scoreA) ? scoreA : -1;
        const validB = Number.isFinite(scoreB) ? scoreB : -1;

        return validB - validA;
    });

    html += "<div class='finding-browser'>" +
        "<div class='finding-filters'>" +

        "<div class='finding-filter'>" +
        "<label>Risk band</label>" +
        "<select aria-label='Filter by risk band' data-finding-filter='band'>" +
        "<option value='all'>All risk bands</option>" +
        "<option value='critical'>Critical</option>" +
        "<option value='very_high'>Very High</option>" +
        "<option value='moderate'>Moderate</option>" +
        "<option value='low'>Low</option>" +
        "<option value='informational'>Informational</option>" +
        "<option value='unclassified'>Unclassified</option>" +
        "</select></div>" +

        "<div class='finding-filter'>" +
        "<label>Priority</label>" +
        "<select aria-label='Filter by priority' data-finding-filter='priority'>" +
        "<option value='all'>All priorities</option>" +
        "<option value='immediate'>Immediate</option>" +
        "<option value='urgent'>Urgent</option>" +
        "<option value='planned'>Planned</option>" +
        "<option value='routine'>Routine</option>" +
        "<option value='manual_review'>Manual Review</option>" +
        "</select></div>" +

        "<div class='finding-filter'>" +
        "<label>Classification</label>" +
        "<select aria-label='Filter by classification' data-finding-filter='classification'>" +
        "<option value='all'>All findings</option>" +
        "<option value='classified'>Classified</option>" +
        "<option value='unclassified'>Unclassified</option>" +
        "</select></div>" +

        "<button type='button' class='secondary' " +
        "data-finding-reset>Reset filters</button>" +
        "</div>" +

        "<p class='finding-filter-count' aria-live='polite' " +
        "data-finding-count>Showing " + safe(findings.length) + " of " + safe(findings.length) + " findings · Sorted by highest risk score</p>" +

        "<div class='finding-results'><table><thead><tr>" +
        "<th>ID</th><th>Asset</th><th>Category</th>" +
        "<th>Severity</th><th>Risk Score</th><th>Risk Band</th>" +
        "<th>Risk Priority</th><th>Status</th><th>Message</th>" +
        "<th>Recommendation</th><th>Details</th><th>AI Remediation</th>" +
        "</tr></thead><tbody>";

    sortedFindings.forEach(function(f) {
        const score = f.risk_score == null
            ? NaN : Number(f.risk_score);

        const rawBand = String(f.risk_band || "").toLowerCase();
        const classified = Number.isFinite(score) &&
            validBands.includes(rawBand);

        const band = classified ? rawBand : "unclassified";

        const rawPriority = String(
            f.risk_priority || ""
        ).toLowerCase();

        const priority = classified &&
            validPriorities.includes(rawPriority)
            ? rawPriority : "manual_review";

        const actionable = allowRemediation && [
            "warning", "critical", "error"
        ].includes(String(f.status || "").toLowerCase());

        html += "<tr data-risk-band='" + safe(band) +
            "' data-risk-priority='" + safe(priority) +
            "' data-classification='" +
            (classified ? "classified" : "unclassified") + "'>" +

            "<td>" + safe(f.id) + "</td>" +
            "<td>" + safe(f.asset || "--") + "</td>" +
            "<td>" + safe(f.category || "--") + "</td>" +
            "<td>" + safe(f.severity || "--") + "</td>" +
            "<td>" + safe(f.risk_score == null ? "--" : f.risk_score) + "</td>" +
            "<td>" + safe(f.risk_band || "--") + "</td>" +
            "<td>" + safe(f.risk_priority || "--") + "</td>" +
            "<td><span class='" + statusClass(f.status) + "'>" +
            safe(f.status || "--") + "</span></td>" +
            "<td>" + safe(f.message || "--") + "</td>" +
            "<td>" + safe(f.recommendation || "--") + "</td>" +
            "<td>" + renderFindingDetails(f) + "</td>" +
            "<td>" + (actionable
                ? "<button type='button' class='secondary' " +
                  "data-remediation-finding='" + safe(f.id) + "'>" +
                  "Generate</button>"
                : "<span class='muted'>Not required</span>") +
            "</td></tr>";
    });

    html += "</tbody></table></div></div>";

    return html;
}

function applyFindingFilters(container) {
    if (!container) {
        return;
    }

    const band = container.querySelector(
        "[data-finding-filter='band']"
    ).value;

    const priority = container.querySelector(
        "[data-finding-filter='priority']"
    ).value;

    const classification = container.querySelector(
        "[data-finding-filter='classification']"
    ).value;

    const rows = container.querySelectorAll(
        ".finding-results tbody tr"
    );

    let visible = 0;

    rows.forEach(function(row) {
        const matches =
            (band === "all" || row.dataset.riskBand === band) &&
            (priority === "all" ||
                row.dataset.riskPriority === priority) &&
            (classification === "all" ||
                row.dataset.classification === classification);

        row.hidden = !matches;

        if (matches) {
            visible++;
        }
    });

    const count = container.querySelector("[data-finding-count]");

    if (count) {
        count.textContent =
            "Showing " + visible + " of " + rows.length +
            " findings · Sorted by highest risk score";
    }
}

document.addEventListener("change", function(event) {
    if (!event.target.matches("[data-finding-filter]")) {
        return;
    }

    applyFindingFilters(event.target.closest(".finding-browser"));
});

document.addEventListener("click", function(event) {
    const button = event.target.closest("[data-finding-reset]");

    if (!button) {
        return;
    }

    const container = button.closest(".finding-browser");

    if (!container) {
        return;
    }

    container.querySelectorAll("[data-finding-filter]").forEach(
        function(select) {
            select.value = "all";
        }
    );

    applyFindingFilters(container);
});

async function refreshAIProvider() {
    const status = document.getElementById("aiProviderStatus");

    try {
        const data = await getJSON("/api/settings/ai-provider");

        status.textContent = data.configured
            ? "OpenAI provider configured · " + (data.storage || "server-side")
            : "OpenAI provider not configured.";

    } catch (error) {
        status.textContent = "Unable to check AI provider: " + error.message;
    }
}

async function saveAIProvider() {
    const input = document.getElementById("aiAPIKey");
    const button = document.getElementById("saveAIKeyButton");
    const message = document.getElementById("aiProviderMessage");
    const key = input.value.trim();

    if (!key) {
        message.textContent = "Enter an API key first.";
        return;
    }

    button.disabled = true;
    message.textContent = "Saving API key...";

    try {
        const data = await getJSON("/api/settings/ai-provider", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({api_key: key})
        });

        input.value = "";
        message.textContent = data.configured
            ? "API key saved in server memory."
            : "Provider configuration was not confirmed.";

        await refreshAIProvider();

    } catch (error) {
        message.textContent = "Unable to save API key: " + error.message;
    } finally {
        button.disabled = false;
    }
}

async function removeAIProvider() {
    const message = document.getElementById("aiProviderMessage");

    if (!confirm("Remove the OpenAI API key from server memory?")) {
        return;
    }

    message.textContent = "Removing API key...";

    try {
        await getJSON("/api/settings/ai-provider", {
            method: "DELETE"
        });

        document.getElementById("aiAPIKey").value = "";
        message.textContent = "OpenAI API key removed.";
        await refreshAIProvider();

    } catch (error) {
        message.textContent = "Unable to remove API key: " + error.message;
    }
}

function renderRemediation(solution) {
    const list = function(items) {
        if (!Array.isArray(items) || items.length === 0) {
            return "<p class='muted'>None provided.</p>";
        }

        return "<ul>" + items.map(function(item) {
            return "<li>" + safe(item) + "</li>";
        }).join("") + "</ul>";
    };

    const steps = (solution.steps || []).map(function(step, index) {
        return "<div class='remediation-card'>" +
            "<h4>" + (index + 1) + ". " + safe(step.title) + "</h4>" +
            "<p>" + safe(step.description) + "</p>" +
            (step.command
                ? "<pre><code>" + safe(step.command) + "</code></pre>"
                : "") +
            (step.impact
                ? "<p><b>Impact:</b> " + safe(step.impact) + "</p>"
                : "") +
            "</div>";
    }).join("");

    return "<div class='remediation-card'>" +
        "<p><b>Provider:</b> " + safe(solution.provider) +
        " · <b>Model:</b> " + safe(solution.model || "Default") + "</p>" +
        "<p><b>Confidence:</b> " + safe(solution.confidence) + "</p>" +
        "<h3>Summary</h3><p>" + safe(solution.summary) + "</p>" +
        "<h3>Root cause</h3><p>" + safe(solution.root_cause) + "</p>" +
        "<h3>Risk</h3><p>" + safe(solution.risk) + "</p>" +
        "<h3>Recommended steps</h3>" + steps +
        "<h3>Verification</h3>" + list(solution.verification) +
        "<h3>Rollback</h3>" + list(solution.rollback) +
        "<h3>Assumptions</h3>" + list(solution.assumptions) +
        "<p class='notice'>Advisory only. Review and approve all commands " +
        "before executing them. No changes have been made to your system.</p>" +
        "</div>";
}

async function generateRemediation(findingID) {
    const results = document.getElementById("remediationResults");

    if (!selectedScanId) {
        results.textContent = "Select a saved scan first.";
        return;
    }

    results.textContent = "Generating remediation plan. Please wait...";

    try {
        const url = "/api/history/" +
            encodeURIComponent(selectedScanId) +
            "/findings/" +
            encodeURIComponent(findingID) +
            "/remediation";

        const solution = await getJSON(url, {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({additional_context: ""})
        });

        results.innerHTML = renderRemediation(solution);

    } catch (error) {
        results.textContent =
            "Remediation generation failed: " + error.message;
    }
}

document.addEventListener("click", function(event) {
    const button = event.target.closest("[data-remediation-finding]");

    if (!button) {
        return;
    }

    generateRemediation(button.dataset.remediationFinding);
});

async function refreshMetrics() {
    const data = await getJSON("/api/metrics");

    document.getElementById("cpu").textContent =
        Number(data.cpu_percent).toFixed(1) + "%";

    document.getElementById("memory").textContent =
        Number(data.memory_percent).toFixed(1) + "%";

    document.getElementById("memoryDetail").textContent =
        Number(data.memory_used_gb).toFixed(1) + " GB used of " +
        Number(data.memory_total_gb).toFixed(1) + " GB";

    setBar("cpuBar", data.cpu_percent);
    setBar("memoryBar", data.memory_percent);
}

async function refreshOverview() {
    const data = await getJSON("/api/overview");

    const inv = data.inventory;
    const report = data.checks;

    document.getElementById("hostname").textContent =
        inv.hostname || "--";

    document.getElementById("os").textContent =
        [inv.os.platform, inv.os.version, inv.kernel.arch]
            .filter(Boolean).join(" · ");

    const cloud = inv.cloud || {};

    document.getElementById("hostDetails").innerHTML =
        "<p><b>CPU:</b> " + safe(inv.cpu.model || "Unknown") +
        " · " + safe(inv.cpu.cores) + " cores</p>" +
        "<p><b>Cloud:</b> " + safe(cloud.provider || "Not detected") +
        " · " + safe(cloud.instance_name || "") +
        " · " + safe(cloud.zone || "") + "</p>" +
        "<p><b>Virtualization:</b> " +
        safe(inv.virtualization.type || "Unknown") + "</p>";

    document.getElementById("disks").innerHTML = renderTable(
        ["Device", "Mount", "Size GB", "Used GB", "Usage"],
        (inv.disk || []).map(function(d) {
            return [
                d.device,
                d.mount,
                d.size_gb,
                d.used_gb,
                d.used_percent + "%"
            ];
        })
    );

    document.getElementById("services").innerHTML = renderTable(
        ["Service", "State", "Sub-state", "Enabled"],
        (inv.services || []).map(function(s) {
            return [
                s.name,
                s.state,
                s.sub_state,
                s.enabled ? "Yes" : "No"
            ];
        })
    );

    const docker = inv.docker;

    if (!docker) {
        document.getElementById("docker").textContent =
            "Docker inventory unavailable.";
    } else {
        document.getElementById("docker").innerHTML =
            "<p>CLI: " +
            (docker.cli_available ? "Available" : "Unavailable") +
            " | Daemon: " +
            (docker.daemon_available ? "Available" : "Unavailable") +
            "</p>" +
            renderTable(
                ["Container", "Image", "State", "Health"],
                (docker.containers || []).map(function(c) {
                    return [
                        c.name,
                        c.image,
                        c.state,
                        c.health || "--"
                    ];
                })
            );
    }

    const findings = report.findings || [];
    document.getElementById("checks").innerHTML = renderFindings(findings);
}

let selectedScanId = "";

async function refreshHistory() {
    const records = await getJSON("/api/history");
    const container = document.getElementById("history");

    container.innerHTML = "";

    if (!Array.isArray(records) || records.length === 0) {
        container.textContent =
            "No saved assessments yet. Run your first assessment.";
        return;
    }

    const headers = [
        "Date", "Overall Status", "Passed", "Warnings",
        "Critical", "Errors", "Findings", "Action"
    ];

    const table = document.createElement("table");
    const thead = document.createElement("thead");
    const headerRow = document.createElement("tr");

    headers.forEach(function(label) {
        const th = document.createElement("th");
        th.textContent = label;
        headerRow.appendChild(th);
    });

    thead.appendChild(headerRow);
    table.appendChild(thead);

    const tbody = document.createElement("tbody");

    records.forEach(function(item) {
        const row = document.createElement("tr");
        const summary = item.summary || {};

        const values = [
            item.created_at
                ? new Date(item.created_at).toLocaleString()
                : "",
            item.overall_status || "",
            summary.passed ?? 0,
            summary.warnings ?? 0,
            summary.critical ?? 0,
            summary.errors ?? 0,
            item.finding_count ?? 0
        ];

        values.forEach(function(value) {
            const cell = document.createElement("td");
            cell.textContent = String(value);
            row.appendChild(cell);
        });

        const actionCell = document.createElement("td");
        const button = document.createElement("button");

        button.type = "button";
        button.className = "secondary";
        button.textContent = "View";

        button.addEventListener("click", function() {
            viewScan(String(item.id));
        });

        actionCell.appendChild(button);
        row.appendChild(actionCell);
        tbody.appendChild(row);
    });

    table.appendChild(tbody);
    container.appendChild(table);

    const selectionStillExists = records.some(function(item) {
        return String(item.id) === selectedScanId;
    });

    if ((!selectedScanId || !selectionStillExists) &&
        records[0] && records[0].id) {
        await viewScan(String(records[0].id));
    }
}

let selectedCloudResources = [];

function renderCloudResourceRows(query) {
    const container = document.getElementById("cloudResourceResults");
    if (!container) return;

    const term = String(query || "").trim().toLowerCase();

    const filtered = selectedCloudResources.filter(function(resource) {
        let searchable = [
            resource.id,
            resource.name,
            resource.type,
            resource.provider,
            resource.project_id,
            resource.region,
            resource.zone
        ].join(" ");

        try {
            searchable += " " + JSON.stringify(resource.labels || {});
            searchable += " " + JSON.stringify(resource.properties || {});
        } catch (_) {
            // Keep the basic resource fields searchable if serialization fails.
        }

        return searchable.toLowerCase().includes(term);
    });

    if (filtered.length === 0) {
        container.innerHTML = "<p class='muted'>No matching cloud resources.</p>";
        return;
    }

    const displayLimit = 200;
    const displayed = filtered.slice(0, displayLimit);

    let html = "<p class='muted'>Showing " +
        displayed.length + " of " + filtered.length + " matching resources.</p>";

    html += "<table><thead><tr>" +
        "<th>Resource</th><th>Type</th><th>Region / Zone</th><th>Details</th>" +
        "</tr></thead><tbody>";

    displayed.forEach(function(resource) {
        const details = {
            id: resource.id || "",
            name: resource.name || "",
            type: resource.type || "",
            provider: resource.provider || "",
            project_id: resource.project_id || "",
            region: resource.region || "",
            zone: resource.zone || "",
            labels: resource.labels || {},
            properties: resource.properties || {}
        };

        html += "<tr>" +
            "<td>" + safe(resource.name || resource.id || "--") + "</td>" +
            "<td>" + safe(resource.type || "--") + "</td>" +
            "<td>" + safe([resource.region, resource.zone].filter(Boolean).join(" / ") || "--") + "</td>" +
            "<td><details class='finding-details'>" +
                "<summary>View resource details</summary>" +
                "<div class='finding-detail-content'>" +
                    renderEvidenceValue(details, 0) +
                "</div>" +
            "</details></td>" +
            "</tr>";
    });

    html += "</tbody></table>";

    if (filtered.length > displayLimit) {
        html += "<p class='muted'>Refine the search to view additional resources.</p>";
    }

    container.innerHTML = html;
}

function renderCloudInventory(inventory) {
    const container = document.getElementById("cloudInventory");
    if (!container) return;

    selectedCloudResources = [];

    if (!inventory || typeof inventory !== "object") {
        container.innerHTML =
            "<p class='muted'>No cloud inventory was collected for this scan.</p>" +
            "<p class='muted'>For a new GCP assessment, configure " +
            "<code>AUDITOR_GCP_PROJECT_ID</code> and Application Default Credentials " +
            "before starting the dashboard.</p>";
        return;
    }

    const resources = Array.isArray(inventory.resources)
        ? inventory.resources
        : [];

    const coverage = Array.isArray(inventory.coverage)
        ? inventory.coverage
        : [];

    selectedCloudResources = resources;

    const countsByType = new Map();

    resources.forEach(function(resource) {
        const type = String(resource.type || "unknown");
        countsByType.set(type, (countsByType.get(type) || 0) + 1);
    });

    let html = "<div class='metrics'>" +
        "<div class='metric'><span>Provider</span><strong>" +
            safe(inventory.provider || "Unknown") + "</strong></div>" +
        "<div class='metric'><span>Project / Account</span><strong>" +
            safe(inventory.project_id || inventory.account_id || "--") + "</strong></div>" +
        "<div class='metric'><span>Total resources</span><strong>" +
            resources.length + "</strong></div>" +
        "<div class='metric'><span>Coverage categories</span><strong>" +
            coverage.length + "</strong></div>" +
        "</div>";

    html += "<h3>Collection Coverage</h3>";

    if (coverage.length === 0) {
        html += "<p class='muted'>No cloud collection coverage details were recorded.</p>";
    } else {
        html += "<table><thead><tr>" +
            "<th>Category</th><th>Status</th><th>Resources</th>" +
            "<th>Duration</th><th>Message</th>" +
            "</tr></thead><tbody>";

        coverage.forEach(function(item) {
            const status = String(item.status || "unknown");
            const cssClass = statusClass(status) || "muted";

            html += "<tr>" +
                "<td>" + safe(item.category || "--") + "</td>" +
                "<td><span class='" + cssClass + "'>" +
                    safe(status.replace(/_/g, " ").toUpperCase()) +
                "</span></td>" +
                "<td>" + safe(item.resource_count ?? 0) + "</td>" +
                "<td>" + safe(item.duration_ms ?? 0) + " ms</td>" +
                "<td>" + safe(item.message || "--") + "</td>" +
                "</tr>";
        });

        html += "</tbody></table>";
    }

    html += "<h3>Resources by Type</h3>";

    if (countsByType.size === 0) {
        html += "<p class='muted'>No cloud resources were discovered.</p>";
    } else {
        html += "<table><thead><tr><th>Resource type</th><th>Count</th>" +
            "</tr></thead><tbody>";

        countsByType.forEach(function(count, type) {
            html += "<tr><td>" + safe(type) + "</td><td>" +
                count + "</td></tr>";
        });

        html += "</tbody></table>";
    }

    html += "<h3>Discovered Resources</h3>" +
        "<label for='cloudResourceSearch'>Filter by name, ID, type, region, or properties</label>" +
        "<input id='cloudResourceSearch' type='search' " +
        "placeholder='Search cloud resources...' autocomplete='off'>" +
        "<div id='cloudResourceResults'></div>";

    container.innerHTML = html;

    const search = document.getElementById("cloudResourceSearch");
    if (search) {
        search.addEventListener("input", function() {
            renderCloudResourceRows(search.value);
        });
    }

    renderCloudResourceRows("");
}

async function viewScan(id) {
    try {
        const record = await getJSON("/api/history/" + encodeURIComponent(id));
        const report = record.report;
        selectedScanId = String(record.id);
        renderCloudInventory(report.cloud_inventory);

        document.getElementById("historyDetail").innerHTML =
            "<p><b>Scan ID:</b> " + safe(record.id) + "</p>" +
            "<p><b>Date:</b> " +
            safe(new Date(record.created_at).toLocaleString()) + "</p>" +
            "<p><b>Overall status:</b> " +
            safe(report.overall_status) + "</p>" +
            "<h3>Findings</h3>" +
            renderFindings(report.findings || [], true);

        showAssessment(report);
    } catch (error) {
        document.getElementById("historyDetail").textContent =
            "Unable to load scan: " + error.message;
    }
}
function showAssessment(report) {
    const summary = report.summary || {};
    const passed = Number(summary.passed || 0);
    const warnings = Number(summary.warnings || 0);
    const critical = Number(summary.critical || 0);
    const errors = Number(summary.errors || 0);
    const total = passed + warnings + critical + errors;

    document.getElementById("totalChecks").textContent = total;
    document.getElementById("passedChecks").textContent = passed;
    document.getElementById("warningChecks").textContent = warnings;
    document.getElementById("criticalChecks").textContent = critical;
    document.getElementById("errorChecks").textContent = errors;

    const modules = report.modules || [];
    const skipped = modules.filter(function(module) {
        return String(module.status || "").toLowerCase() === "skipped";
    }).length;

    document.getElementById("latestAssessment").textContent =
        "Overall: " + (report.overall_status || "Unknown") +
        " | Total checks: " + total +
        " | Skipped modules: " + skipped;

    // Module execution results
    let moduleHTML = "<h3>Module Execution</h3>" +
        "<table><thead><tr>" +
        "<th>Module</th><th>Status</th><th>Duration</th><th>Details</th>" +
        "</tr></thead><tbody>";

    modules.forEach(function(module) {
        const status = String(module.status || "unknown");
        const cssClass = statusClass(status) || "skipped";

        moduleHTML += "<tr>" +
            "<td>" + safe(module.name || "--") + "</td>" +
            "<td><span class='" + cssClass + "'>" +
            safe(status.toUpperCase()) + "</span></td>" +
            "<td>" + safe(module.duration_ms ?? 0) + " ms</td>" +
            "<td>" + safe(module.message || "--") + "</td>" +
            "</tr>";
    });

    moduleHTML += "</tbody></table>";

    document.getElementById("moduleResults").innerHTML =
        modules.length
            ? moduleHTML
            : "<h3>Module Execution</h3><p class='muted'>No module details available.</p>";

    // Data collection coverage
    const coverage = report.coverage || [];

    let coverageHTML = "<h3>Data Collection Coverage</h3>";

    if (coverage.length === 0) {
        coverageHTML +=
            "<p class='muted'>No coverage information available for this assessment.</p>";
    } else {
        coverageHTML +=
            "<table><thead><tr>" +
            "<th>Provider</th>" +
            "<th>Category</th>" +
            "<th>Status</th>" +
            "<th>Resources</th>" +
            "<th>Duration</th>" +
            "<th>Details</th>" +
            "</tr></thead><tbody>";

        coverage.forEach(function(item) {
            const status = String(item.status || "unknown");
            const cssClass = statusClass(status) || "skipped";

            coverageHTML += "<tr>" +
                "<td>" + safe(item.provider || "--") + "</td>" +
                "<td>" + safe(item.category || "--") + "</td>" +
                "<td><span class='" + cssClass + "'>" +
                safe(status.replace(/_/g, " ").toUpperCase()) +
                "</span></td>" +
                "<td>" + safe(item.resource_count ?? 0) + "</td>" +
                "<td>" + safe(item.duration_ms ?? 0) + " ms</td>" +
                "<td>" + safe(item.message || "--") + "</td>" +
                "</tr>";
        });

        coverageHTML += "</tbody></table>";
    }

    document.getElementById("coverageResults").innerHTML = coverageHTML;
}


async function refreshAll() {
    const status = document.getElementById("status");
    status.textContent = "Refreshing dashboard...";

    const results = await Promise.allSettled([
        refreshMetrics(),
        refreshOverview(),
        refreshHistory(),
        refreshAIProvider()
    ]);

    const failed = results.filter(function(result) {
        return result.status === "rejected";
    });

    if (failed.length > 0) {
        status.textContent =
            "Connected · " + failed.length + " section(s) need attention";
        status.title = failed.map(function(result) {
            return result.reason
                ? result.reason.message
                : "Unknown refresh error";
        }).join("; ");
    } else {
        status.textContent = "Connected";
        status.title = "All dashboard sections refreshed successfully.";
    }
}

async function runScan() {
    const button = document.getElementById("scanButton");
    const message = document.getElementById("scanMessage");
    const status = document.getElementById("status");

    button.disabled = true;
    message.textContent = "Assessment running. Please wait...";
    status.textContent = "Assessment in progress...";

    try {
        const record = await getJSON("/api/scan", {
            method: "POST"
        });

        message.textContent =
            "Assessment completed and saved. Refreshing dashboard...";

        await refreshAll();

        if (record && record.id) {
            message.textContent =
                "Assessment completed and saved. Scan ID: " + record.id;
        }
    } catch (error) {
        message.textContent = "Assessment failed: " + error.message;
        status.textContent = "Assessment failed";
        status.title = error.message;
    } finally {
        button.disabled = false;
    }
}

refreshAll();

setInterval(function() {
    refreshMetrics().catch(function(error) {
        document.getElementById("status").textContent =
            "Metrics refresh failed";
        document.getElementById("status").title = error.message;
    });
}, 5000);

setInterval(function() {
    refreshOverview().catch(function(error) {
        document.getElementById("status").textContent =
            "Inventory refresh failed";
        document.getElementById("status").title = error.message;
    });
}, 30000);

setInterval(function() {
    refreshHistory().catch(function(error) {
        document.getElementById("status").textContent =
            "History refresh failed";
        document.getElementById("status").title = error.message;
    });
}, 60000);
</script>

</body>
</html>`
