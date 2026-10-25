
/*
 * NetGuardian Dashboard JavaScript
 *
 * Features:
 * - Notifications
 * - Device discovery
 * - Trust management
 * - Manual quarantine/release actions
 * - Alert resolution
 * - Isolated attack simulation
 * - Live security alerts
 * - Live network traffic
 *
 * Refresh interval: 5 seconds
 *
 * Main dashboard statistics and device-table polling
 * are already implemented in index.html.
 */

"use strict";

const DASHBOARD_REFRESH_INTERVAL = 5000;


// ========================================================
// 1. Notifications
// ========================================================

let toastTimer = null;

function showToast(message, isError = false) {
    const toast = document.getElementById("toast");

    if (!toast) {
        if (isError) {
            console.error("[NetGuardian]", message);
        }
        return;
    }

    toast.textContent = message;
    toast.style.borderColor = isError
        ? "#ef4444"
        : "#10b981";

    toast.classList.remove("hidden");

    if (toastTimer !== null) {
        clearTimeout(toastTimer);
    }

    toastTimer = setTimeout(() => {
        toast.classList.add("hidden");
        toastTimer = null;
    }, 4000);
}


// ========================================================
// 2. API Request Helper
// ========================================================

async function requestJSON(url, options = {}) {
    const response = await fetch(url, {
        cache: "no-store",
        ...options
    });

    let data;

    try {
        data = await response.json();
    } catch {
        throw new Error(
            `Invalid server response (HTTP ${response.status})`
        );
    }

    if (!response.ok || data?.status === "error") {
        throw new Error(
            data?.message ||
            `Request failed (HTTP ${response.status})`
        );
    }

    return data;
}


// ========================================================
// 3. Active Network Discovery
// ========================================================

async function triggerDiscovery() {
    showToast("Initiating active network device discovery...");

    try {
        const data = await requestJSON("/api/scan", {
            method: "POST"
        });

        showToast(
            `Discovery completed: ${data.count ?? 0} devices detected.`
        );

        // Refresh the page after a manually requested scan.
        // Regular device monitoring does not reload the page.
        setTimeout(() => {
            location.reload();
        }, 1000);

    } catch (error) {
        showToast(
            `Device discovery failed: ${error.message}`,
            true
        );
    }
}


// ========================================================
// 4. Device Trust Management
// ========================================================

async function toggleTrust(deviceId, trusted) {
    try {
        const data = await requestJSON(
            `/api/device/${deviceId}/trust`,
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    trusted: Boolean(trusted)
                })
            }
        );

        showToast(
            data.message || "Device trust status updated."
        );

        // Existing live device and statistics polling
        // will reflect this change automatically.

    } catch (error) {
        showToast(
            `Failed to update trust state: ${error.message}`,
            true
        );
    }
}


// ========================================================
// 5. Manual Quarantine / Release
// ========================================================

async function toggleQuarantine(deviceId, action) {
    const enforcement = await requestJSON(`/api/device/${deviceId}/enforcement`).catch(() => null);
    const managed = enforcement?.has_ownership && enforcement.state !== "RELEASED";
    if (document.body.dataset.protectionMode === "LIVE" || managed) {
        const panel = document.getElementById("router-enforcement");
        if (panel && Number(panel.dataset.deviceId) === Number(deviceId)) {
            await prepareRouterChange(action);
        } else location.href = `/device/${deviceId}#router-enforcement`;
        return;
    }
    if (!confirm(`${action === "release" ? "Release the DEMO marker" : "Mark this device quarantined in DEMO mode"}? This does not block Wi-Fi.`)) return;
    if (!["quarantine", "release"].includes(action)) {
        showToast("Invalid quarantine action.", true);
        return;
    }

    try {
        const data = await requestJSON(
            `/api/device/${deviceId}/quarantine`,
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ action })
            }
        );

        showToast(
            data.message || "Device state updated."
        );

        if (/^\/device\/\d+$/.test(location.pathname)) location.reload();
        // The live device table will update automatically.
        // The actual enforcement behavior is controlled
        // by the backend protection configuration.

    } catch (error) {
        showToast(
            `Device action failed: ${error.message}`,
            true
        );
    }
}


// ========================================================
// 6. Alert Resolution
// ========================================================

async function resolveAlert(alertId) {
    try {
        const data = await requestJSON(
            `/api/alerts/${alertId}/resolve`,
            {
                method: "POST"
            }
        );

        showToast(
            data.message || "Alert marked as resolved."
        );

        // Update the feed immediately.
        await updateLiveAlerts();

    } catch (error) {
        showToast(
            `Failed to resolve alert: ${error.message}`,
            true
        );
    }
}


// ========================================================
// 7. Isolated Attack Simulation
// ========================================================

function renderSimulationHistory(events) {
    const tbody = document.getElementById(
        "simulation-history-body"
    );

    if (!tbody) {
        return;
    }

    tbody.replaceChildren();

    if (!Array.isArray(events) || events.length === 0) {
        const row = tbody.insertRow();
        const cell = row.insertCell();

        cell.colSpan = 5;
        cell.textContent = "No simulation events yet.";
        return;
    }

    for (const event of [...events].reverse()) {
        const row = tbody.insertRow();

        const fields = [
            event.timestamp || "â€”",
            String(
                event.scenario || "unknown"
            ).replaceAll("_", " "),
            `${event.risk_score ?? "â€”"}/100`,
            event.risk_level || "â€”",
            event.would_quarantine
                ? "YES (demo only)"
                : "No"
        ];

        for (const value of fields) {
            row.insertCell().textContent = value;
        }
    }
}


async function loadSimulationHistory() {
    const feedback = document.getElementById(
        "simulation-feedback"
    );

    if (!feedback) {
        return;
    }

    try {
        const data = await requestJSON(
            "/api/simulate/history"
        );

        renderSimulationHistory(
            data.events || []
        );

    } catch (error) {
        feedback.textContent =
            `Could not load simulation history: ${error.message}`;
    }
}


async function triggerSimulation(attackType) {
    const feedback = document.getElementById(
        "simulation-feedback"
    );

    const scenarioName = String(
        attackType
    ).replaceAll("_", " ");

    if (feedback) {
        feedback.textContent =
            `Running ${scenarioName}...`;
    }

    try {
        const data = await requestJSON(
            `/api/simulate/${encodeURIComponent(attackType)}`,
            {
                method: "POST"
            }
        );

        if (feedback) {
            feedback.textContent = data.message;
        }

        showToast(data.message);

        await loadSimulationHistory();

        // Simulation data is isolated from actual
        // device, alert, and traffic records.

    } catch (error) {
        const message =
            `Simulation error: ${error.message}`;

        if (feedback) {
            feedback.textContent = message;
        }

        showToast(message, true);
    }
}


// ========================================================
// 8. Shared DOM Helpers
// ========================================================

function createElement(tag, className = "", text = null) {
    const element = document.createElement(tag);

    if (className) {
        element.className = className;
    }

    if (text !== null && text !== undefined) {
        element.textContent = String(text);
    }

    return element;
}


function displayTimestamp(timestamp) {
    const value = String(timestamp || "");

    if (value.includes("T")) {
        return value.split("T")[1];
    }

    return value || "-";
}


function normalizeSeverity(severity) {
    const value = String(
        severity || "LOW"
    ).toUpperCase();

    return ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        .includes(value)
        ? value
        : "LOW";
}


// ========================================================
// 9. Live Security Alerts Feed
// ========================================================

let alertsRefreshInProgress = false;


function createAlertElement(alert) {
    const severity = normalizeSeverity(
        alert.severity
    );

    const severityLower = severity.toLowerCase();

    const item = createElement(
        "div",
        `alert-item alert-${severityLower}`
    );

    // Alert icon
    const iconContainer = createElement(
        "div",
        "alert-icon"
    );

    const icon = createElement(
        "i",
        severity === "CRITICAL"
            ? "fa-solid fa-skull"
            : severity === "HIGH"
                ? "fa-solid fa-triangle-exclamation"
                : "fa-solid fa-circle-exclamation"
    );

    iconContainer.appendChild(icon);
    item.appendChild(iconContainer);

    // Main alert content
    const content = createElement(
        "div",
        "alert-content"
    );

    // Alert metadata
    const metadata = createElement(
        "div",
        "alert-meta"
    );

    const severityBadge = createElement(
        "span",
        `badge badge-${severityLower}`,
        severity
    );

    metadata.appendChild(severityBadge);

    const alertType = String(
        alert.alert_type || "unknown_event"
    )
        .replaceAll("_", " ")
        .toUpperCase();

    metadata.appendChild(
        createElement(
            "span",
            "alert-type",
            alertType
        )
    );

    metadata.appendChild(
        createElement(
            "span",
            "alert-time",
            displayTimestamp(alert.timestamp)
        )
    );

    content.appendChild(metadata);

    // Alert description
    content.appendChild(
        createElement(
            "p",
            "alert-description",
            alert.description ||
                "Security event detected."
        )
    );

    // Associated device information
    const deviceInfo = createElement(
        "div",
        "alert-device-info"
    );

    deviceInfo.appendChild(
        document.createTextNode("Host: ")
    );

    deviceInfo.appendChild(
        createElement(
            "code",
            "",
            alert.ip_address || "Unknown"
        )
    );

    const hostname =
        alert.device_name ||
        alert.hostname ||
        "Unknown";

    deviceInfo.appendChild(
        document.createTextNode(
            ` (${hostname})`
        )
    );

    content.appendChild(deviceInfo);
    item.appendChild(content);

    // Resolve action for open alerts
    if (
        String(alert.status || "").toLowerCase() === "open"
    ) {
        const alertId = Number(alert.id);

        if (
            Number.isSafeInteger(alertId) &&
            alertId > 0
        ) {
            const button = createElement(
                "button",
                "btn btn-sm btn-resolve"
            );

            button.type = "button";
            button.title = "Resolve alert";
            button.setAttribute(
                "aria-label",
                `Resolve alert ${alertId}`
            );

            button.appendChild(
                createElement(
                    "i",
                    "fa-solid fa-check"
                )
            );

            button.addEventListener(
                "click",
                () => resolveAlert(alertId)
            );

            item.appendChild(button);
        }
    }

    return item;
}


function renderLiveAlerts(alerts) {
    const container = document.getElementById(
        "alerts-feed-container"
    );

    if (!container) {
        return;
    }

    const counter = document.getElementById(
        "alert-counter"
    );

    const visibleAlerts = alerts.slice(0, 25);

    const fragment = document.createDocumentFragment();

    if (visibleAlerts.length === 0) {
        const emptyState = createElement(
            "div",
            "empty-state"
        );

        emptyState.appendChild(
            createElement(
                "i",
                "fa-solid fa-shield-heart empty-icon"
            )
        );

        emptyState.appendChild(
            createElement(
                "p",
                "",
                "No recent security alerts."
            )
        );

        fragment.appendChild(emptyState);

    } else {
        for (const alert of visibleAlerts) {
            fragment.appendChild(
                createAlertElement(alert)
            );
        }
    }

    // Preserve scroll position when possible.
    const previousScrollTop = container.scrollTop;

    container.replaceChildren(fragment);

    container.scrollTop = previousScrollTop;

    if (counter) {
        counter.textContent =
            `${visibleAlerts.length} Recent`;
    }
}


async function updateLiveAlerts() {
    const container = document.getElementById(
        "alerts-feed-container"
    );

    if (
        !container ||
        alertsRefreshInProgress ||
        document.hidden
    ) {
        return;
    }

    alertsRefreshInProgress = true;

    try {
        const alerts = await requestJSON(
            "/api/alerts"
        );

        if (!Array.isArray(alerts)) {
            throw new Error(
                "Unexpected alerts API response"
            );
        }

        // Match the API's recent-alert ordering.
        // It already excludes alerts cleared
        // before the last reset.
        renderLiveAlerts(alerts);

    } catch (error) {
        console.error(
            "[NetGuardian] Live alerts refresh failed:",
            error
        );

        // Preserve the last successfully displayed feed.

    } finally {
        alertsRefreshInProgress = false;
    }
}


// ========================================================
// 10. Live Network Traffic
// ========================================================

let trafficRefreshInProgress = false;


function renderLiveTraffic(traffic) {
    const tbody = document.getElementById(
        "traffic-table-body"
    );

    if (!tbody) {
        return;
    }

    const fragment = document.createDocumentFragment();

    function addCell(row, value, className = "") {
        const cell = createElement(
            "td",
            className,
            value
        );

        row.appendChild(cell);

        return cell;
    }

    const recentTraffic = traffic.slice(0, 25);

    for (const packet of recentTraffic) {
        const row = createElement("tr");

        addCell(
            row,
            displayTimestamp(packet.timestamp)
        );

        addCell(
            row,
            `${packet.source_ip || "-"} ` +
            `(${packet.device_name || "Host"})`
        );

        addCell(
            row,
            packet.destination_ip || "-"
        );

        addCell(
            row,
            packet.protocol || "-"
        );

        addCell(
            row,
            packet.destination_port ?? "-"
        );

        addCell(
            row,
            packet.dns_query || "-"
        );

        addCell(
            row,
            `${packet.packet_size ?? 0} B`
        );

        fragment.appendChild(row);
    }

    if (recentTraffic.length === 0) {
        const row = createElement("tr");

        const cell = createElement(
            "td",
            "",
            "No network traffic records available."
        );

        cell.colSpan = 7;
        row.appendChild(cell);

        fragment.appendChild(row);
    }

    tbody.replaceChildren(fragment);
}


async function updateLiveTraffic() {
    const tbody = document.getElementById(
        "traffic-table-body"
    );

    if (
        !tbody ||
        trafficRefreshInProgress ||
        document.hidden
    ) {
        return;
    }

    trafficRefreshInProgress = true;

    try {
        const traffic = await requestJSON(
            "/api/traffic"
        );

        if (!Array.isArray(traffic)) {
            throw new Error(
                "Unexpected traffic API response"
            );
        }

        renderLiveTraffic(traffic);

    } catch (error) {
        console.error(
            "[NetGuardian] Live traffic refresh failed:",
            error
        );

        // Preserve the last confirmed traffic data.

    } finally {
        trafficRefreshInProgress = false;
    }
}


// ========================================================
// 11. Dashboard Initialization
// ========================================================

function refreshLiveDashboardData() {
    if (document.hidden) {
        return;
    }

    updateLiveAlerts();
    updateLiveTraffic();
}


document.addEventListener(
    "DOMContentLoaded",
    () => {
        // Simulation history is only loaded on pages
        // containing the simulation interface.
        loadSimulationHistory();

        // Load alerts and traffic immediately.
        refreshLiveDashboardData();

        // Continue polling every five seconds.
        setInterval(
            refreshLiveDashboardData,
            DASHBOARD_REFRESH_INTERVAL
        );

        // Refresh immediately when user returns
        // to the browser tab.
        document.addEventListener(
            "visibilitychange",
            () => {
                if (!document.hidden) {
                    refreshLiveDashboardData();
                }
            }
        );
    }
);

async function refreshEngineHealth() {
    const label = document.getElementById("engine-status");
    if (!label || document.hidden) return;
    try {
        const health = await requestJSON("/api/health");
        const capture = health.capture;
        label.textContent = `Capture: ${capture.status} · ${capture.traffic_records_persisted} saved`;
        const indicator = document.querySelector(".pulse-indicator");
        if (indicator) {
            indicator.style.backgroundColor = capture.status === "CAPTURING" ? "#10b981"
                : capture.worker_error || capture.status === "WRITE_ERROR" ? "#ef4444" : "#94a3b8";
            indicator.style.animation = capture.status === "CAPTURING" ? "" : "none";
        }
        label.title = capture.status === "UNVERIFIED"
            ? "Worker is running; recent database writes have not been verified."
            : `${health.protection_mode || "DEMO"} mode; automatic quarantine disabled.`;
    } catch { label.textContent = "Monitoring status unavailable"; }
}
async function renameDevice(id, name) {
    try {
        const result = await requestJSON(`/api/device/${id}/name`, {
            method: "POST", headers: {"Content-Type": "application/json"},
            body: JSON.stringify({device_name: name})
        });
        showToast(result.message);
        location.reload();
    } catch (error) { showToast(error.message, true); }
}
document.addEventListener("DOMContentLoaded", () => {
    refreshEngineHealth();
    setInterval(refreshEngineHealth, 5000);
});
