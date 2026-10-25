"use strict";
function showIncidentReview(data) {
    document.getElementById('incident-status').textContent=`${data.writes_locked?'INCIDENT LOCKDOWN retained':data.closure_approved?'Incident closure verified; marker retained':'Lock file missing: requires administrator investigation'} · Cause ${data.root_cause} · ${data.ready_for_manual_live?'Manual LIVE requires explicit mode approval':'LIVE activation unavailable'}`;
    const list=document.getElementById('incident-checklist');list.replaceChildren();
    for(const check of data.checks){const p=document.createElement('p');p.textContent=`${check.passed?'PASS':'PENDING'} — ${check.name}`;list.appendChild(p);}
    document.getElementById('incident-evidence').textContent=data.verified_at?JSON.stringify({verified_at:data.verified_at,filters:data.filters,identity_reviews:data.identity_reviews,read_error:data.read_error,requests:data.requests,configuration_writes:data.configuration_writes},null,2):'No router request is made until you select read-only verification.';
}
document.addEventListener('DOMContentLoaded',()=>{
    const button=document.getElementById('incident-readonly');if(!button)return;
    let busy=false;
    const close=document.getElementById('incident-close');
    const update=()=>{button.disabled=busy||!routerAdmin?.authenticated;if(close)close.disabled=busy||!routerAdmin?.authenticated;};setInterval(update,1000);update();
    button.addEventListener('click',async()=>{
        busy=true;update();
        try{showIncidentReview(await routerPost('/api/router/incident/verify'));}
        catch(error){document.getElementById('incident-status').textContent=error.message;}
        finally{busy=false;update();}
    });
    requestJSON('/api/router/incident').then(showIncidentReview).catch(error=>{document.getElementById('incident-status').textContent=error.message;});
    document.getElementById('incident-close-form')?.addEventListener('submit',async event=>{
        event.preventDefault();if(busy)return;
        const fields=new FormData(event.target);
        const data=Object.fromEntries(fields.entries());
        data.non_target_device_ids=String(fields.get('non_target_device_ids')).split(',').map(value=>Number(value.trim()));
        data.observations=Object.fromEntries(['target_denied','non_targets_unaffected','wired_management_unaffected','target_reconnected_after_release','original_settings_restored'].map(key=>[key,fields.has(key)]));
        if(!await confirmAdministratorAction('Approve incident closure using these audited hardware results and observations? No router write or mode change will occur. The marker will be retained. LIVE must still be enabled explicitly.'))return;
        busy=true;update();
        try{
            const result=await routerPost('/api/router/incident/close',{...data,confirmed:true});
            showToast(result.message);await routerSession();
            showIncidentReview(await requestJSON('/api/router/incident'));
        }catch(error){document.getElementById('incident-status').textContent=error.message;}
        finally{busy=false;update();}
    });
});
