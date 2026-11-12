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

		report := audit.Run(ctx, scanner, audit.Config{
			TargetPath: targetPath,
			Timeout:    5 * time.Minute,
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

th, td {
    padding: 10px;
    text-align: left;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
}

th {
    color: var(--muted);
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

function renderFindings(findings, allowRemediation) {
    if (!findings || findings.length === 0) {
        return "<p class='muted'>No findings.</p>";
    }

    let html = "<table><thead><tr>" +
        "<th>ID</th><th>Asset</th><th>Category</th>" +
        "<th>Severity</th><th>Status</th><th>Message</th>" +
        "<th>Recommendation</th><th>AI Remediation</th>" +
        "</tr></thead><tbody>";

    findings.forEach(function(f) {
        const actionable = allowRemediation && ["warning", "critical", "error"].includes(
            String(f.status || "").toLowerCase()
        );

        html += "<tr>" +
            "<td>" + safe(f.id) + "</td>" +
            "<td>" + safe(f.asset || "--") + "</td>" +
            "<td>" + safe(f.category || "--") + "</td>" +
            "<td>" + safe(f.severity || "--") + "</td>" +
            "<td><span class='" + statusClass(f.status) + "'>" +
                safe(f.status || "--") + "</span></td>" +
            "<td>" + safe(f.message || "--") + "</td>" +
            "<td>" + safe(f.recommendation || "--") + "</td>" +
            "<td>" + (actionable
                ? "<button type='button' class='secondary' " +
                  "data-remediation-finding='" + safe(f.id) + "'>" +
                  "Generate</button>"
                : "<span class='muted'>Not required</span>") +
            "</td></tr>";
    });

    return html + "</tbody></table>";
}

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

async function viewScan(id) {
    try {
        const record = await getJSON("/api/history/" + encodeURIComponent(id));
        const report = record.report;
        selectedScanId = String(record.id);

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



refreshAll();
refreshAIProvider();

setInterval(refreshMetrics, 5000);
setInterval(refreshOverview, 30000);
setInterval(refreshHistory, 60000);
</script>

</body>
</html>`
