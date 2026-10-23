function showToast(message, isError = false) {
    const toast = document.getElementById("toast");
    if (!toast) return;
    toast.textContent = message;
    toast.style.borderColor = isError ? "#ef4444" : "#10b981";
    toast.classList.remove("hidden");
    setTimeout(() => {
        toast.classList.add("hidden");
    }, 4000);
}

async function triggerDiscovery() {
    showToast("Initiating active network device discovery...");
    try {
        const res = await fetch("/api/scan", { method: "POST" });
        const data = await res.json();
        showToast(`Discovery completed: ${data.count} devices detected.`);
        setTimeout(() => location.reload(), 1000);
    } catch (e) {
        showToast("Error during device discovery: " + e, true);
    }
}

async function toggleTrust(deviceId, trusted) {
    try {
        const res = await fetch(`/api/device/${deviceId}/trust`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ trusted: trusted })
        });
        const data = await res.json();
        showToast(data.message);
        setTimeout(() => location.reload(), 600);
    } catch (e) {
        showToast("Failed to update trust state: " + e, true);
    }
}

async function toggleQuarantine(deviceId, action) {
    try {
        const res = await fetch(`/api/device/${deviceId}/quarantine`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ action: action })
        });
        const data = await res.json();
        showToast(data.message);
        setTimeout(() => location.reload(), 600);
    } catch (e) {
        showToast("Failed to execute quarantine action: " + e, true);
    }
}

async function resolveAlert(alertId) {
    try {
        const res = await fetch(`/api/alerts/${alertId}/resolve`, { method: "POST" });
        const data = await res.json();
        showToast("Alert marked as resolved.");
        setTimeout(() => location.reload(), 500);
    } catch (e) {
        showToast("Failed to resolve alert: " + e, true);
    }
}

function renderSimulationHistory(events) {
    const tbody = document.getElementById("simulation-history-body");
    if (!tbody) return;
    tbody.replaceChildren();
    if (!events.length) {
        const row = tbody.insertRow();
        const cell = row.insertCell();
        cell.colSpan = 5;
        cell.textContent = "No simulation events yet.";
        return;
    }
    for (const event of [...events].reverse()) {
        const row = tbody.insertRow();
        const fields = [
            event.timestamp || "—",
            (event.scenario || "unknown").replaceAll("_", " "),
            `${event.risk_score ?? "—"}/100`,
            event.risk_level || "—",
            event.would_quarantine ? "YES (demo only)" : "No"
        ];
        for (const value of fields) row.insertCell().textContent = value;
    }
}

async function loadSimulationHistory() {
    const feedback = document.getElementById("simulation-feedback");
    if (!feedback) return;
    try {
        const res = await fetch("/api/simulate/history", { cache: "no-store" });
        const data = await res.json();
        if (!res.ok || data.status !== "success") throw new Error(data.message || `HTTP ${res.status}`);
        renderSimulationHistory(data.events || []);
    } catch (error) {
        feedback.textContent = `Could not load simulation history: ${error.message}`;
    }
}

async function triggerSimulation(attackType) {
    const feedback = document.getElementById("simulation-feedback");
    if (feedback) feedback.textContent = `Running ${attackType.replaceAll("_", " ")}...`;
    try {
        const res = await fetch(`/api/simulate/${encodeURIComponent(attackType)}`, { method: "POST" });
        const data = await res.json();
        if (!res.ok || data.status !== "success") throw new Error(data.message || `HTTP ${res.status}`);
        if (feedback) feedback.textContent = data.message;
        showToast(data.message);
        await loadSimulationHistory();
        // Do not reload: results should remain visible and real-device stats are unchanged.
    } catch (error) {
        const message = `Simulation error: ${error.message}`;
        if (feedback) feedback.textContent = message;
        showToast(message, true);
    }
}

document.addEventListener("DOMContentLoaded", loadSimulationHistory);

// Background telemetry updater
async function updateStats() {
    try {
        const res = await fetch("/api/stats");
        if (!res.ok) return;
        const stats = await res.json();

        const elTotal = document.getElementById("stat-total-devices");
        if (elTotal) elTotal.textContent = stats.total_devices;

        const elOnline = document.getElementById("stat-online-devices");
        if (elOnline) elOnline.textContent = stats.online_devices;

        const elQuarantined = document.getElementById("stat-quarantined-devices");
        if (elQuarantined) elQuarantined.textContent = stats.quarantined_devices;

        const elAlerts = document.getElementById("stat-open-alerts");
        if (elAlerts) elAlerts.textContent = stats.open_alerts;

        const elRisk = document.getElementById("stat-high-risk");
        if (elRisk) elRisk.textContent = stats.high_risk_devices;
    } catch (e) {
        // Silently retry on next interval
    }
}

// Auto-refresh counters every 5 seconds
setInterval(updateStats, 5000);


// Refresh live network traffic every 5 seconds.
async function updateLiveTraffic() {
    const tbody = document.getElementById("traffic-table-body");
    if (!tbody) return;

    try {
        const response = await fetch("/api/traffic", {
            cache: "no-store"
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const traffic = await response.json();

        if (!Array.isArray(traffic)) {
            throw new Error("Unexpected traffic API response");
        }

        // Build rows safely without injecting raw network data as HTML.
        const fragment = document.createDocumentFragment();

        function addCell(row, value) {
            const cell = document.createElement("td");
            cell.textContent = String(value ?? "-");
            row.appendChild(cell);
        }

        for (const packet of traffic.slice(0, 25)) {
            const row = document.createElement("tr");

            const timestamp = packet.timestamp || "";
            const displayTime = timestamp.includes("T")
                ? timestamp.split("T")[1]
                : timestamp;

            addCell(row, displayTime);
            addCell(
                row,
                `${packet.source_ip || "-"} (${packet.device_name || "Host"})`
            );
            addCell(row, packet.destination_ip || "-");
            addCell(row, packet.protocol || "-");
            addCell(row, packet.destination_port ?? "-");
            addCell(row, packet.dns_query || "-");
            addCell(row, `${packet.packet_size ?? 0} B`);

            fragment.appendChild(row);
        }

        if (traffic.length === 0) {
            const row = document.createElement("tr");
            const cell = document.createElement("td");
            cell.colSpan = 7;
            cell.textContent = "No traffic records available.";
            row.appendChild(cell);
            fragment.appendChild(row);
        }

        tbody.replaceChildren(fragment);

    } catch (error) {
        console.error("[NetGuardian] Live traffic refresh failed:", error);
    }
}

// Start refreshing once the page is ready.
document.addEventListener("DOMContentLoaded", () => {
    updateLiveTraffic();
    setInterval(updateLiveTraffic, 5000);
});
