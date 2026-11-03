package dashboard

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/cloudbusket/ai-auditor/audit-engine/internal/checks"
	"github.com/cloudbusket/ai-auditor/audit-engine/internal/inventory"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
)

// NewHandler creates the authenticated dashboard HTTP handler.
func NewHandler(password string) (http.Handler, error) {
	if password == "" {
		return nil, errors.New("dashboard password is required")
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/", dashboardPage)
	mux.HandleFunc("/api/overview", overviewHandler)
	mux.HandleFunc("/api/metrics", metricsHandler)
	mux.HandleFunc("/api/checks", checksHandler)

	return authenticate(password, mux), nil
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
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(indexHTML))
}

// overviewHandler returns the actual server inventory and health checks.
func overviewHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	inv, err := inventory.Collect()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
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
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cpuValues, err := cpu.Percent(500*time.Millisecond, false)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "Unable to collect CPU metrics: " + err.Error(),
		})
		return
	}

	vm, err := mem.VirtualMemory()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "Unable to collect memory metrics: " + err.Error(),
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

// checksHandler returns security and health findings.
func checksHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
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
    border: none;
    padding: 10px 15px;
    border-radius: 7px;
    font-weight: bold;
    cursor: pointer;
}

table {
    width: 100%;
    border-collapse: collapse;
}

th, td {
    padding: 10px;
    text-align: left;
    border-bottom: 1px solid var(--border);
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
        <div class="muted">Infrastructure Health Dashboard</div>
    </div>

    <div>
        <span id="status">Connecting...</span>
        <button onclick="refreshAll()">Refresh</button>
    </div>
</header>

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
        <div class="muted">Security Findings</div>
        <div class="metric" id="findings">--</div>
        <div id="findingDetail" class="muted"></div>
    </section>

</div>

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
async function getJSON(url) {
    const response = await fetch(url, {cache: "no-store"});

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

async function refreshMetrics() {
    const data = await getJSON("/api/metrics");

    document.getElementById("cpu").textContent =
        data.cpu_percent.toFixed(1) + "%";

    document.getElementById("memory").textContent =
        data.memory_percent.toFixed(1) + "%";

    document.getElementById("memoryDetail").textContent =
        data.memory_used_gb.toFixed(1) + " GB used of " +
        data.memory_total_gb.toFixed(1) + " GB";

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

    document.getElementById("findings").textContent =
        findings.length;

    document.getElementById("findingDetail").textContent =
        "Overall status: " + (report.overall_status || "Unknown");

    document.getElementById("checks").innerHTML = renderTable(
        ["ID", "Category", "Status", "Message", "Recommendation"],
        findings.map(function(f) {
            return [
                f.id,
                f.category,
                f.status,
                f.message,
                f.recommendation || "--"
            ];
        })
    );
}

async function refreshAll() {
    document.getElementById("status").textContent = "Refreshing...";

    try {
        await Promise.all([
            refreshMetrics(),
            refreshOverview()
        ]);

        document.getElementById("status").textContent =
            "Connected · " + new Date().toLocaleTimeString();

    } catch (error) {
        document.getElementById("status").textContent =
            "Error: " + error.message;
    }
}

refreshAll();

setInterval(refreshMetrics, 5000);
setInterval(refreshOverview, 30000);
</script>

</body>
</html>`
