"use strict";
let routerAdmin = null;
let routerPlan = null;
let routerOwnedMac = null;
let routerBusy = false;
let routerLastState = null;
let routerPlanVersion = 0;

function invalidateRouterPlan() {
    routerPlanVersion += 1;
    routerPlan = null;
    const execute = document.getElementById('router-execute');
    if (execute) execute.disabled = true;
}
function assertSelectedTarget(plan) {
    const panel = document.getElementById('router-enforcement');
    const routeId = location.pathname.match(/^\/device\/(\d+)$/)?.[1];
    const expectedMac = plan.action === 'quarantine' ? panel?.dataset.deviceMac : routerOwnedMac;
    const scope = [...document.querySelectorAll('input[name="router-ssid"]:checked')].map(input => input.value).sort();
    if (!panel || Number(routeId) !== plan.device_id || Number(panel.dataset.deviceId) !== plan.device_id ||
        !expectedMac || expectedMac.toUpperCase() !== plan.mac ||
        (plan.action === 'quarantine' && JSON.stringify(scope) !== JSON.stringify([...plan.ssid_indices].sort()))) {
        invalidateRouterPlan();
        throw new Error('Selected device, MAC or SSID differs from this plan. No change sent. Refresh and prepare again.');
    }
}

function confirmAdministratorAction(description) {
    const dialog = document.getElementById("router-confirm-dialog");
    if (dialog.open) return Promise.resolve(false);
    document.getElementById("router-confirm-description").textContent = description;
    dialog.returnValue = "cancel";
    return new Promise(resolve => {
        dialog.addEventListener("close", () => resolve(dialog.returnValue === "approve"), {once: true});
        dialog.showModal();
    });
}

async function routerSession() {
    const previousMode = routerAdmin?.protection_mode;
    routerAdmin = await requestJSON("/api/admin/session");
    document.body.dataset.protectionMode = routerAdmin.protection_mode;
    const label = document.getElementById("router-admin-status");
    if (label) label.textContent = `${routerAdmin.authenticated ? "Administrator signed in" : "Administrator signed out"} · ${routerAdmin.protection_mode} mode · New LIVE blocks ${routerAdmin.writes_enabled ? "enabled with confirmation" : "disabled"} · Managed LIVE release remains available in DEMO${routerAdmin.configured ? "" : " · Configure the administrator password locally first"}`;
    document.getElementById("mode-live").disabled = routerAdmin.writes_locked || !routerAdmin.authenticated || routerAdmin.protection_mode === "LIVE";
    document.getElementById("mode-live").title = routerAdmin.writes_locked ? "Complete verified incident closure on Threat Detection. Administrator sign-in alone cannot clear this lock." : "Administrator approval enables manual LIVE for this runtime; no router write occurs.";
    if (routerAdmin.writes_locked && label) label.textContent += ' · INCIDENT LOCKDOWN: all router configuration writes, including release, disabled. Review closure on Threat Detection.';
    document.getElementById("mode-demo").disabled = !routerAdmin.authenticated || routerAdmin.protection_mode === "DEMO";
    const pending = routerAdmin.pending_managed_devices || [];
    document.getElementById("mode-outstanding").textContent = pending.length
        ? `Managed router operations still need review/release: ${pending.map(row => `device ${row.device_id}: ${row.state}`).join(", ")}. DEMO does not remove those rules.`
        : "No outstanding managed router quarantines are recorded.";
    if (previousMode && previousMode !== routerAdmin.protection_mode) {
        routerPlan = null;
        const button = document.getElementById("router-execute");
        if (button) button.disabled = true;
        if (!routerBusy) location.reload();
    }
    updateRouterButtons();
    return routerAdmin;
}
async function switchRouterMode(mode) {
    const text = mode === "LIVE"
        ? "Enable manual LIVE mode? This makes no router changes. Every quarantine still needs a reviewed, explicit confirmation. Automatic quarantine stays disabled."
        : "Return to DEMO? New LIVE blocks will be disabled. Existing router rules remain until you explicitly Release them; release/recovery will still be available.";
    if (!await confirmAdministratorAction(text)) return;
    try {
        await routerPost("/api/protection-mode", {mode, confirmed: true});
        routerPlan = null;
        location.reload();
    } catch (error) { routerError(error); }
}
function updateRouterButtons() {
    if (!document.getElementById("router-enforcement")) return;
    const state = routerLastState;
    const pending = routerAdmin?.writes_locked || routerBusy || ["REQUESTED", "APPLYING"].includes(state?.state);
    const owned = state?.has_ownership && state?.state !== "RELEASED";
    const identityButton = document.getElementById('router-identity-submit');
    if (identityButton) identityButton.disabled = routerBusy || !routerAdmin?.authenticated;
    document.getElementById("router-plan-block").disabled = pending || !routerAdmin?.authenticated || routerAdmin?.protection_mode !== "LIVE" || owned;
    document.getElementById("router-plan-release").disabled = pending || !routerAdmin?.authenticated || !owned;
    document.getElementById("router-plan-recover").disabled = pending || !routerAdmin?.authenticated || !state?.has_ownership;
    document.getElementById("router-reconcile").disabled = routerBusy || !routerAdmin?.authenticated || !state?.has_ownership;
}

async function routerPost(url, body = {}) {
    if (!routerAdmin) await routerSession();
    return requestJSON(url, {method: "POST", headers: {"Content-Type": "application/json", "X-CSRF-Token": routerAdmin.csrf_token}, body: JSON.stringify(body)});
}
function routerError(error) {
    showToast(error.message, true);
    const feedback = document.getElementById("router-admin-feedback");
    if (feedback) feedback.textContent = error.message;
    const message = document.getElementById("router-enforcement-message");
    if (message) message.textContent = error.message;
}
async function refreshRouterEnforcement() {
    const panel = document.getElementById("router-enforcement");
    if (!panel || document.hidden) return;
    try {
        const state = await requestJSON(`/api/device/${panel.dataset.deviceId}/enforcement`);
        routerLastState = state;
        updateRouterButtons();
        if (state.device_id !== undefined && Number(state.device_id) !== Number(panel.dataset.deviceId)) throw new Error('Enforcement response belongs to another device. Refresh the page.');
        routerOwnedMac = state.mac_address || null;
        document.getElementById("router-enforcement-state").textContent = `${state.state}${state.verification_stale ? " (last verification stale; reconcile)" : ""}`;
        document.getElementById("router-enforcement-message").textContent = `${state.error_code ? state.error_code + ": " : ""}${state.message || ""}`;
        document.getElementById("router-verification").textContent = `Router rule enforcement: ${state.verified_enforced === true ? "verified on last read" : state.verified_enforced === false ? "not enforced on last read" : "UNKNOWN"}. Scope: ${state.ssid_indices?.join(", ") || "none"}${state.ssid_indices?.length && !state.scope_complete ? " (partial SSID scope)" : ""}. Last verified: ${state.verified_at || "never"}${state.verification_stale ? " (stale; Reconcile to refresh)" : ""}. Wi-Fi client: ${state.client_connected === true ? "still listed as connected; immediate disconnection unverified" : state.client_connected === false ? "not listed on last router read" : "not observed"}.`;
    } catch (error) { routerError(error); }
}
async function prepareRouterChange(action) {
    const panel = document.getElementById("router-enforcement");
    invalidateRouterPlan();
    const version = routerPlanVersion;
    document.getElementById("router-execute").disabled = true;
    try {
        const auth = await routerSession();
        if (!auth.authenticated) throw new Error("Sign in with the NetGuardian administrator password first.");
        const plan = await routerPost(`/api/device/${panel.dataset.deviceId}/router-quarantine/plan`, {
            action, mac: action === "quarantine" ? panel.dataset.deviceMac : routerOwnedMac,
            ssid_indices: [...document.querySelectorAll('input[name="router-ssid"]:checked')].map(input => input.value),
            allow_enable: document.getElementById("router-allow-enable").checked
        });
        if (version !== routerPlanVersion) return;
        if (plan.idempotent) {
            document.getElementById("router-plan-preview").textContent = "Managed state already verified. No router write was sent.";
            await refreshRouterEnforcement();
            return;
        }
        assertSelectedTarget(plan);
        routerPlan = Object.freeze(plan);
        const changes = plan.after.map(after => {
            const before = plan.before.find(item => item.index === after.index);
            return `SSID ${after.index}: ${before.mode} [${before.entries.join(", ") || "empty"}] -> ${after.mode} [${after.entries.join(", ") || "empty"}]`;
        });
        document.getElementById("router-plan-preview").textContent = [
            `${plan.action.toUpperCase()} device ${plan.device_id} MAC ${plan.mac}`,
            `Firmware ${plan.firmware.SoftwareVersion}; plan expires in ${plan.expires_in_seconds} seconds.`,
            ...changes, "All unrelated settings and rules are retained.", `Recovery: ${plan.recovery}`,
            plan.writes_locked ? "INCIDENT LOCKDOWN: all router writes are disabled pending separate approval." : plan.can_execute ? "Awaiting explicit administrator confirmation. No router change has been made." : "New LIVE blocks are disabled in DEMO. Managed releases are still permitted."
        ].join("\n");
        document.getElementById("router-execute").disabled = !plan.can_execute;
        if (!plan.can_execute) showToast("Plan prepared only. New blocks require manual LIVE mode.");
    } catch (error) {
        document.getElementById("router-plan-preview").textContent = `Plan was not prepared: ${error.message}`;
        if (error.message.includes('private Wi-Fi address')) {
            const details=document.getElementById('router-identity-details');
            if(details){details.open=true;details.scrollIntoView({behavior:'smooth',block:'center'});}
        }
        routerError(error);
    }
}
async function confirmRouterChange() {
    if (!routerPlan) return;
    const plan = routerPlan;
    try { assertSelectedTarget(plan); } catch (error) { routerError(error); return; }
    const description = `${plan.action.toUpperCase()} DEVICE ${plan.device_id}, MAC ${plan.mac}, SSID ${plan.ssid_indices.join(', ')}.\nBefore: ${JSON.stringify(plan.before)}\nAfter: ${JSON.stringify(plan.after)}\n${plan.recovery}\nProceed with this exact router configuration change?`;
    if (!await confirmAdministratorAction(description)) return;
    if (routerPlan !== plan) { routerError(new Error('Plan changed while confirmation was open. Prepare again.')); return; }
    try { assertSelectedTarget(plan); } catch (error) { routerError(error); return; }
    const button = document.getElementById("router-execute");
    button.disabled = true;
    routerPlan = null;
    routerBusy = true;
    updateRouterButtons();
    document.getElementById("router-action-status").textContent = "REQUESTED: confirmation submitted; awaiting verified router results.";
    const progress = setInterval(refreshRouterEnforcement, 500);
    try {
        const result = await routerPost("/api/router/quarantine/execute", {plan_id: plan.plan_id, confirmed: true,
            device_id: plan.device_id, mac: plan.mac, ssid_indices: plan.ssid_indices, expected_digest: plan.expected_digest});
        showToast(result.message);
        document.getElementById("router-action-status").textContent = `${result.enforcement.state}: ${result.message}`;
    } catch (error) {
        document.getElementById("router-action-status").textContent = error.message;
        routerError(error);
    } finally { clearInterval(progress); routerBusy = false; }
    await refreshRouterEnforcement();
}

document.addEventListener("DOMContentLoaded", () => {
    routerSession().catch(routerError);
    setInterval(() => { if (!document.hidden) routerSession().catch(routerError); }, 15000);
    document.getElementById("mode-live")?.addEventListener("click", () => switchRouterMode("LIVE"));
    document.getElementById("mode-demo")?.addEventListener("click", () => switchRouterMode("DEMO"));
    const login = document.getElementById("router-admin-login");
    if (login) login.addEventListener("submit", async event => {
        event.preventDefault();
        const field = login.elements.password;
        try {
            await routerSession();
            await routerPost("/api/admin/login", {password: field.value});
            await routerSession();
            showToast("Administrator signed in. Router configuration unchanged.");
        } catch (error) { routerError(error); }
        finally { field.value = ""; }
    });
    document.getElementById("router-admin-logout")?.addEventListener("click", async () => {
        try { await routerPost("/api/admin/logout"); routerPlan = null; const button = document.getElementById("router-execute"); if (button) button.disabled = true; await routerSession(); }
        catch (error) { routerError(error); }
    });
    const panel = document.getElementById("router-enforcement");
    if (!panel) return;
    document.getElementById('router-identity-form')?.addEventListener('submit', async event => {
        event.preventDefault();if(routerBusy)return;
        invalidateRouterPlan();
        const fields=new FormData(event.target);
        const mac=String(fields.get('mac')||'').trim().toUpperCase();
        const ip=String(fields.get('ip')||'').trim();
        const indices=[...document.querySelectorAll('input[name="router-ssid"]:checked')].map(input=>input.value);
        const feedback=document.getElementById('router-identity-status');
        if(mac!==panel.dataset.deviceMac.toUpperCase()){
            feedback.textContent='The MAC read from the phone differs from this selected record. Run discovery and open the matching device; no binding or router change was made.';
            return;
        }
        if(!await confirmAdministratorAction(`Confirm that DEVICE ${panel.dataset.deviceId}, MAC ${mac}, IP ${ip}, SSID ${indices.join(', ')} matches the Wi-Fi details you read from that physical device. This verifies identity only and makes no router configuration change.`))return;
        routerBusy=true;updateRouterButtons();
        try{
            const result=await routerPost(`/api/device/${panel.dataset.deviceId}/router-identity/verify`,{
                mac,ip,ssid_indices:indices,stable_mac_confirmed:fields.has('stable_mac_confirmed'),
                non_management:fields.has('non_management'),confirmed:true
            });
            feedback.textContent=result.message;
            document.getElementById('router-plan-preview').textContent='Identity verified. Prepare a fresh quarantine plan to review the exact device, MAC and SSID changes. No router change has been made.';
            await refreshRouterEnforcement();showToast(result.message);
        }catch(error){feedback.textContent=error.message;routerError(error);}
        finally{routerBusy=false;updateRouterButtons();}
    });
    document.querySelectorAll('input[name="router-ssid"], #router-allow-enable').forEach(input => input.addEventListener('change', invalidateRouterPlan));
    document.getElementById("router-plan-block").addEventListener("click", () => prepareRouterChange("quarantine"));
    document.getElementById("router-plan-release").addEventListener("click", () => prepareRouterChange("release"));
    document.getElementById("router-plan-recover").addEventListener("click", () => prepareRouterChange("recover"));
    document.getElementById("router-execute").addEventListener("click", confirmRouterChange);
    document.getElementById("router-reconcile").addEventListener("click", async () => {
        try { await routerPost(`/api/device/${panel.dataset.deviceId}/router-quarantine/reconcile`); await refreshRouterEnforcement(); }
        catch (error) { routerError(error); }
    });
    refreshRouterEnforcement();
    setInterval(refreshRouterEnforcement, 5000);
});
