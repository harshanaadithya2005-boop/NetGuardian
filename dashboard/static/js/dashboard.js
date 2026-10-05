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

async function triggerSimulation(attackType) {
    showToast(`Injecting scenario: ${attackType.replace('_', ' ')}...`);
    try {
        const res = await fetch(`/api/simulate/${attackType}`, { method: "POST" });
        const data = await res.json();
        showToast(data.message);
        setTimeout(() => location.reload(), 1200);
    } catch (e) {
        showToast("Simulation error: " + e, true);
    }
}

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
