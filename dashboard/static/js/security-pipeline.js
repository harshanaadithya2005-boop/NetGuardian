"use strict";
let lastVivaDecision = null;
let securityBusy = false;
let policyFormInitialized = false;
function securityLine(parent, text) { const p=document.createElement('p');p.textContent=text;parent.appendChild(p); }
function renderSecurity(data, lab=false) {
    const risks=document.getElementById(lab?'viva-evidence':'security-risks');risks.replaceChildren();
    const evidence=lab?risks:document.getElementById('security-evidence');if(!lab)evidence.replaceChildren();
    const decisions=lab?risks:document.getElementById('security-decisions');if(!lab)decisions.replaceChildren();
    for(const risk of data.risks) {
        securityLine(risks,`${risk.device_name || 'Device '+risk.device_id} [ID ${risk.device_id}] (${risk.ip_address}) · ${risk.source} · ${risk.previous_risk_score} → ${risk.risk_score}/100 · ${risk.severity} · Evaluated ${risk.evaluated_at}${risk.stale?' · STALE: waiting for monitor evaluation':''}`);
        securityLine(risks,risk.explanation);
        for(const detection of risk.detections)securityLine(evidence,`${detection.type} · ${detection.severity} · Confidence ${Math.round(detection.confidence*100)}% · Evidence #${detection.evidence_id} · ${detection.observed_at} · ${detection.explanation}`);
    }
    if(!data.risks.length)securityLine(risks,'No recorded risk evaluations yet. Capture must observe the device traffic before packet-based threats can be assessed.');
    lastVivaDecision=lab?null:lastVivaDecision;
    for(const decision of data.decisions) {
        securityLine(decisions,`${decision.initiation} · ${decision.source} · Device ${decision.device_id} · ${decision.state} · Risk ${decision.details.risk_score}/100 · ${decision.requested_at} · ${decision.details.reason}`);
        if(lab && decision.state==='AUTO_SIMULATED')lastVivaDecision=decision.id;
    }
    if(!data.decisions.length)securityLine(decisions,'No automatic decisions recorded.');
}
function refreshSecurityButtons() {
    document.querySelectorAll('[data-security-admin]').forEach(b=>b.disabled=securityBusy||!routerAdmin?.authenticated);
    const release=document.getElementById('viva-release');
    if(release)release.disabled=securityBusy||!routerAdmin?.authenticated||!lastVivaDecision;
}
async function refreshSecurity() {
    const panel=document.getElementById('security-pipeline');if(!panel||document.hidden)return;
    try {
        const data=await requestJSON('/api/security'+(panel.dataset.deviceId?`?device_id=${panel.dataset.deviceId}`:''));
        renderSecurity(data);
        if(!policyFormInitialized) {
            const form=document.getElementById('security-policy-form');
            form.elements.mode.value=data.policy.mode;form.elements.enabled.checked=data.policy.enabled;
            form.elements.min_risk.value=data.policy.min_risk;form.elements.min_confidence.value=data.policy.min_confidence;
            policyFormInitialized=true;
        }
        document.getElementById('security-policy').textContent=`${data.policy.mode} · Policy ${data.policy.enabled?'enabled':'disabled'} · Risk ≥ ${data.policy.min_risk}, confidence ≥ ${data.policy.min_confidence}, ${data.policy.min_independent_indicators} independent indicators within ${data.policy.max_evidence_age_seconds}s · Physical automatic blocking unavailable.`;
        document.getElementById('security-health').textContent=`${data.physical_writes_locked?'INCIDENT LOCKDOWN: physical router writes disabled.':'Manual router actions require their own authorization.'} Scores reflect traffic visible to the capture interface. Re-evaluated by the threat monitor every 15 seconds while running.`;
        refreshSecurityButtons();
    } catch(error){document.getElementById('security-health').textContent=error.message;}
}
async function vivaAction(url,body={}) {
    securityBusy=true;refreshSecurityButtons();
    try {
        const data=await routerPost(url,body);renderSecurity(data.security,true);
        document.getElementById('viva-result').textContent=`ISOLATED PACKET REPLAY · ${data.packet_replay_count||0} packets replayed · 0 packets transmitted · 0 physical router writes · ${data.risk?data.risk.risk_score+'/100':''}`;
    } catch(error){document.getElementById('viva-result').textContent=error.message;}
    finally{securityBusy=false;refreshSecurityButtons();}
}
async function refreshViva() {
    if(!document.getElementById('viva-lab')||securityBusy||document.hidden)return;
    try {
        const data=await requestJSON('/api/security/viva');
        if(securityBusy)return;
        renderSecurity(data.security,true);
        document.getElementById('viva-result').textContent=`Saved ISOLATED PACKET REPLAY · ${data.packet_records} packet records · 0 packets transmitted · 0 physical router writes`;
        refreshSecurityButtons();
    } catch(error){document.getElementById('viva-result').textContent=error.message;}
}
document.addEventListener('DOMContentLoaded',()=>{
    const threat=document.getElementById('security-pipeline');
    const viva=document.getElementById('viva-lab');
    if(!threat&&!viva)return;
    refreshSecurityButtons();setInterval(refreshSecurityButtons,1000);
    if(threat) {
        refreshSecurity();setInterval(refreshSecurity,5000);
        document.getElementById('security-policy-form').addEventListener('submit',async event=>{
            event.preventDefault();const form=event.currentTarget;
            if(!await confirmAdministratorAction('Save the response decision policy? Physical blocking remains unavailable and the incident lock is unchanged.'))return;
            try{await routerPost('/api/security/policy',{confirmed:true,mode:form.elements.mode.value,enabled:form.elements.enabled.checked,min_risk:Number(form.elements.min_risk.value),min_confidence:Number(form.elements.min_confidence.value)});await refreshSecurity();}
            catch(error){showToast(error.message,true);}
        });
    }
    if(viva) {
        refreshViva();setInterval(refreshViva,10000);
        document.querySelectorAll('[data-viva-scenario]').forEach(button=>button.addEventListener('click',()=>vivaAction('/api/security/viva/run',{scenario:button.dataset.vivaScenario})));
        document.getElementById('viva-reset').addEventListener('click',()=>vivaAction('/api/security/viva/reset'));
        document.getElementById('viva-release').addEventListener('click',()=>vivaAction('/api/security/viva/release',{decision_id:lastVivaDecision}));
    }
});
