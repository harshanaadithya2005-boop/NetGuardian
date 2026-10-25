"""Explainable automatic decisions; deliberately has NO router write path."""
from datetime import datetime
import hashlib,json
import config
from database.db import get_connection,is_isolated

def settings():
    conn=get_connection()
    try:
        row=conn.execute('SELECT policy_json FROM response_settings WHERE id=1').fetchone()
        return json.loads(row[0]) if row else dict(config.AUTO_RESPONSE_POLICY,mode='DEMO')
    finally:conn.close()

def set_settings(data):
    current=settings()
    if set(data)-{'enabled','mode','min_risk','min_confidence','min_independent_indicators','max_evidence_age_seconds'}:raise ValueError('Unsupported policy field; physical enforcement is unavailable.')
    current.update(data)
    if type(current['enabled']) is not bool or current['mode'] not in {'DEMO','MANUAL_LIVE','AUTOMATIC_RESPONSE'}:raise ValueError('Invalid policy mode or enabled flag')
    for key,low,high in [('min_risk',40,100),('min_confidence',.5,1),('min_independent_indicators',2,7),('max_evidence_age_seconds',10,300)]:
        if type(current[key]) not in {int,float} or not low<=current[key]<=high:raise ValueError('Invalid policy threshold: '+key)
        if key!='min_confidence' and type(current[key]) is not int:raise ValueError('Integer threshold required: '+key)
    conn=get_connection()
    try:
        conn.execute('BEGIN IMMEDIATE')
        conn.execute('INSERT INTO response_settings VALUES (1,?,?) ON CONFLICT(id) DO UPDATE SET policy_json=excluded.policy_json,updated_at=excluded.updated_at',(json.dumps(current),datetime.now().isoformat()))
        conn.execute('INSERT INTO response_settings_audit (policy_json,timestamp) VALUES (?,?)',(json.dumps(current),datetime.now().isoformat()))
        conn.commit()
    finally:conn.close()
    return current

def eligibility(device,router=None):
    from response import router_quarantine as manual
    if device.get('status')!='online':return False,'Device is not currently online.'
    client=None
    try:
        client=router or manual.new_client()
        manual.validate_device(device['id'],device.get('mac_address'),require_wifi=client.get_connected_wifi_devices(),indices=['0'],
                               management_identity=getattr(client,'management_identity',None) if is_isolated() else None)
        manual.validate_scope(client,['0'])
        _,snapshot=client.probe_quarantine_capabilities()
        if snapshot.ssids['0'].findtext('WifiMacFilterStatus')=='1':return False,'Whitelist mode conflicts with quarantine.'
        conn=get_connection()
        try:
            if is_isolated() and conn.execute("SELECT 1 FROM response_decisions WHERE device_id=? AND state='AUTO_SIMULATED'",(device['id'],)).fetchone():return False,'An automatic simulated quarantine already exists; review or release it before another response.'
            if conn.execute("SELECT 1 FROM router_quarantines WHERE device_id=? AND state IN ('REQUESTED','APPLYING','ACTIVE','FAILED') AND ownership_json!='[]'",(device['id'],)).fetchone():return False,'An existing manual operation requires review.'
            if conn.execute('SELECT 1 FROM router_operation_lease WHERE id=1 AND expires_at>strftime(\'%s\',\'now\')').fetchone():return False,'Another router response is in progress.'
            if conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='device_identity_conflicts'").fetchone() and conn.execute("SELECT 1 FROM device_identity_conflicts WHERE status='open' AND (existing_device_id=? OR ip_address=?)",(device['id'],device.get('ip_address'))).fetchone():return False,'Unresolved discovery identity conflict.'
        finally:conn.close()
        return True,'IP/MAC uniquely matched the current Wi-Fi list and sole enabled scope; protected-device checks passed.'
    except Exception as error:
        safe=manual._safe_error(error);return False,safe.code+': '+safe.message
    finally:
        if router is None and client is not None:client.close()

def evaluate(device,risk,router=None):
    policy=settings();now=datetime.now();source='ISOLATED_PACKET_REPLAY' if is_isolated() else 'LIVE_CAPTURE'
    # An already applied/released simulation cannot be replayed by duplicate evidence.
    conn=get_connection()
    try:
        for row in conn.execute("SELECT id,state,details_json FROM response_decisions WHERE device_id=? AND source=? AND state IN ('AUTO_SIMULATED','RELEASED') ORDER BY id DESC",(device['id'],source)):
            old=json.loads(row['details_json'])
            if old['policy']==policy and old['evidence_ids']==[d.get('evidence_id') for d in risk['detections']]:
                return dict(id=row['id'],state=row['state'],details=old)
    finally:conn.close()
    fresh=[]
    for d in risk['detections']:
        try:age=(now-datetime.fromisoformat(d['observed_at'])).total_seconds()
        except (ValueError,KeyError):continue
        if d['type']!='unknown_device' and d.get('alert_id') and d['confidence']>=policy['min_confidence'] and 0<=age<=policy['max_evidence_age_seconds'] and d.get('risk_contribution',0)>0:fresh.append(d)
    independent={d['incident_group'] for d in fresh}
    state='POLICY_EVALUATED';reason='Risk/evidence below policy thresholds; no response attempted.';action='NONE';eligible=None
    if risk['risk_score']>=policy['min_risk'] and len(independent)>=policy['min_independent_indicators']:
        state='PENDING_REVIEW';reason='Automatic response disabled or mode requires administrator review.'
        if policy['enabled'] and policy['mode']=='AUTOMATIC_RESPONSE':
            eligible,reason=eligibility(device,router)
            if eligible and is_isolated():state='AUTO_SIMULATED';action='SIMULATED_QUARANTINE';reason+=' Isolated synthetic device only; no Wi-Fi or router configuration changed.'
            elif eligible:reason+=' Physical automatic enforcement is unavailable and safety-locked; administrator review required.'
    details=dict(policy=policy,risk_score=risk['risk_score'],evidence_ids=[d.get('evidence_id') for d in risk['detections']],
                 alert_ids=[d['alert_id'] for d in risk['detections'] if d.get('alert_id')],
                 independent_indicators=sorted(independent),reason=reason,eligible=eligible,
                 physical_enforcement_available=False,router_configuration_writes=0)
    signature=hashlib.sha256(json.dumps(dict(policy=policy,evidence=details['evidence_ids'],state=state,reason=reason),sort_keys=True).encode()).hexdigest()
    conn=get_connection()
    try:
        conn.execute('BEGIN IMMEDIATE')
        for previous in conn.execute("SELECT id,state,details_json FROM response_decisions WHERE device_id=? AND source=? AND state IN ('AUTO_SIMULATED','RELEASED') ORDER BY id DESC",(device['id'],source)):
            old=json.loads(previous['details_json'])
            if old['policy']==policy and old['evidence_ids']==details['evidence_ids']:
                conn.commit();return dict(id=previous['id'],state=previous['state'],details=old)
        if state=='AUTO_SIMULATED' and conn.execute("SELECT 1 FROM response_decisions WHERE device_id=? AND state='AUTO_SIMULATED'",(device['id'],)).fetchone():
            state='PENDING_REVIEW';action='NONE';details['eligible']=False
            details['reason']='Another automatic simulated quarantine already owns this device; review/release it first.'
            signature=hashlib.sha256(json.dumps(dict(policy=policy,evidence=details['evidence_ids'],state=state,reason=details['reason']),sort_keys=True).encode()).hexdigest()
        cur=conn.execute('INSERT OR IGNORE INTO response_decisions (device_id,mac_address,source,state,action,signature,details_json,requested_at,verified_at) VALUES (?,?,?,?,?,?,?,?,?)',
                         (device['id'],device.get('mac_address'),source,state,action,signature,json.dumps(details),now.isoformat(),None))
        row=conn.execute('SELECT id,state FROM response_decisions WHERE device_id=? AND signature=? AND source=?',(device['id'],signature,source)).fetchone()
        if cur.rowcount:
            for event in (['DETECTED'] if risk['detections'] else [])+['POLICY_EVALUATED']+([state] if state!='POLICY_EVALUATED' else []):
                conn.execute('INSERT INTO response_events (decision_id,state,details_json,timestamp) VALUES (?,?,?,?)',(row['id'],event,json.dumps(details),now.isoformat()))
        conn.commit();return dict(id=row['id'],state=row['state'],details=details)
    except Exception:conn.rollback();raise
    finally:conn.close()

def release_simulated(decision_id):
    if not is_isolated():raise ValueError('Only isolated simulated decisions can use this release action. Use manual router Release for physical rules.')
    conn=get_connection()
    try:
        conn.execute('BEGIN IMMEDIATE')
        row=conn.execute("SELECT * FROM response_decisions WHERE id=? AND source='ISOLATED_PACKET_REPLAY' AND action='SIMULATED_QUARANTINE'",(decision_id,)).fetchone()
        if not row:raise ValueError('No owned simulated response found')
        if row['state']!='RELEASED':
            now=datetime.now().isoformat()
            for state in ['RELEASE_REQUESTED','RELEASED']:conn.execute('INSERT INTO response_events (decision_id,state,details_json,timestamp) VALUES (?,?,?,?)',(decision_id,state,'{"initiation":"manual","router_writes":0}',now))
            conn.execute("UPDATE response_decisions SET state='RELEASED',verified_at=? WHERE id=?",(now,decision_id))
        conn.commit()
    except Exception:conn.rollback();raise
    finally:conn.close()
