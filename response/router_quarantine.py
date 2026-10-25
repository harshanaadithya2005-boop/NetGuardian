"""Manual Huawei quarantine with persistent intents, verified ownership and recovery.

Nothing in this module starts automatically or accepts a risk-engine trigger.
All writes pass the persistent incident interlock. Dashboard confirmations use
scoped single-use grants; legacy test tools additionally require config gates.
"""
from contextlib import contextmanager
from datetime import datetime
import ipaddress
import json
import os
import secrets
import time

import config
from database.db import get_connection
from database.models import get_device_by_id
from router.huawei_client import HuaweiRouterClient
from router.mac_filter import FilterSnapshot, QuarantineError, WritePermit, normalize_mac, plan_block, plan_release


def now_text():
    return datetime.now().isoformat(timespec='seconds')


def new_client():
    password=os.getenv('HUAWEI_ROUTER_PASSWORD')
    if not password:
        raise QuarantineError('AUTH_NOT_CONFIGURED','Router credentials are not configured. Set the existing Huawei credentials locally.')
    return HuaweiRouterClient(os.getenv('HUAWEI_ROUTER_USERNAME','user'),password,base_url=config.ROUTER_URL)


def local_identities():
    """Read all local adapters; fail closed if management identity is unknown."""
    from scapy.all import get_if_list, get_if_addr, get_if_hwaddr
    ips=set();macs=set()
    for iface in get_if_list():
        # Inactive adapters also belong to the management PC and must remain
        # protected if the operator later switches between Ethernet and Wi-Fi.
        try:
            macs.add(normalize_mac(get_if_hwaddr(iface)))
        except Exception:
            pass
        try:
            ip=get_if_addr(iface)
            if ip and ip!='0.0.0.0' and not ip.startswith('127.'):
                ips.add(ip)
        except Exception:
            continue
    if not ips or not macs:
        raise QuarantineError('HOST_IDENTITY_UNKNOWN','Cannot verify the management PC adapters. No router changes are permitted.')
    return ips,macs


def validate_device(device_id, mac, requester_ip=None, require_wifi=None, blocking=True, indices=None, management_identity=None, identity_session=None):
    dev=get_device_by_id(device_id)
    mac=normalize_mac(mac)
    if not blocking:
        if not dev: raise QuarantineError('INVALID_TARGET','Managed device record is missing; use the saved manual recovery snapshot.')
        return dev
    if not dev or normalize_mac(dev.get('mac_address'))!=mac:
        raise QuarantineError('IDENTITY_CHANGED','Device/MAC identity changed. Rediscover and prepare a new plan.')
    conn=get_connection()
    try:
        if conn.execute('SELECT 1 FROM devices WHERE UPPER(TRIM(mac_address))=? AND id!=? LIMIT 1',(mac,device_id)).fetchone():
            raise QuarantineError('AMBIGUOUS_IDENTITY','Multiple inventory rows claim this MAC. Review identity records before quarantining it.')
    finally: conn.close()
    ip=dev.get('ip_address')
    try:
        address=ipaddress.ip_address(ip)
        network=ipaddress.ip_network(config.TARGET_NETWORK,strict=False)
        if address not in network or address in {network.network_address,network.broadcast_address}:
            raise ValueError()
    except (ValueError,TypeError):
        raise QuarantineError('INVALID_TARGET','Device must have a verified address in the monitored network.')
    if management_identity is not None:
        from database.db import is_isolated
        if not is_isolated():raise QuarantineError('INVALID_CONTEXT','Synthetic management identities are allowed only in an isolated database context.')
        local_ips,local_macs=management_identity
    else:local_ips,local_macs=local_identities()
    protected_ips=local_ips | set(config.PROTECTED_MANAGEMENT_IPS) | {'192.168.8.1',config.GATEWAY_IP}
    if requester_ip: protected_ips.add(requester_ip)
    if ip in protected_ips or mac in local_macs | set(config.PROTECTED_MANAGEMENT_MACS) or any(word in str(dev.get('device_type','')).lower() for word in ('router','gateway','management')):
        raise QuarantineError('PROTECTED_DEVICE','The router, NetGuardian PC and management devices cannot be quarantined.')
    if require_wifi is not None:
        # Match MAC AND current IP in the router's authenticated live client list.
        matches=[w for w in require_wifi if str(w.get('mac','')).upper()==mac and w.get('ip')==ip]
        claims=[w for w in require_wifi if str(w.get('mac','')).upper()==mac or w.get('ip')==ip]
        if len(matches)!=1 or len(claims)!=1:
            raise QuarantineError('WIFI_IDENTITY_UNVERIFIED','Target is not currently verified as this router Wi-Fi client. Reconnect the spare device and refresh.')
        hostname=str(dev.get('hostname') or '').strip().casefold()
        router_name=str(matches[0].get('hostname') or '').strip().casefold()
        if hostname and router_name and hostname!=router_name:
            raise QuarantineError('IDENTITY_CHANGED','Router hostname and inventory identity disagree. Review discovery evidence.')
        if int(mac[:2],16)&2:
            binding=config.STABLE_WIFI_IDENTITY_BINDINGS.get(mac)
            if not binding:
                from router.wifi_identity import lookup
                binding=lookup(device_id,mac,ip,router_name,indices,identity_session)
            if not binding or binding.get('device_id')!=device_id or binding.get('ip')!=ip or not router_name or str(binding.get('hostname','')).casefold()!=router_name or (indices is not None and sorted(binding.get('ssid_indices',[]))!=sorted(indices)):
                raise QuarantineError('RANDOMIZED_IDENTITY_UNVERIFIED','This device uses a private Wi-Fi address. Open "Verify current Wi-Fi identity" below and enter the MAC and IP from this device’s Wi-Fi settings. If its MAC rotates on reconnect, choose Phone MAC on the device and rediscover it. A hostname alone is insufficient.')
    return dev


def validate_scope(client,indices):
    enabled=client.enabled_wifi_scopes()
    if len(enabled)!=1 or indices!=enabled:
        raise QuarantineError('SSID_IDENTITY_UNVERIFIED','This firmware does not identify each client SSID. Require exactly one enabled SSID and select only that verified scope.')
    from router.incident_closure import approved_record
    closure=approved_record()
    if closure:
        report,_=client.probe_quarantine_capabilities()
        if indices!=closure['ssid_indices'] or report.get('firmware')!=closure['firmware']:
            raise QuarantineError('HARDWARE_SCOPE_CHANGED','Firmware or SSID differs from the incident-closure hardware validation. A new safety review is required.')


def _safe_error(error):
    if isinstance(error,QuarantineError): return error
    import requests
    if isinstance(error,requests.RequestException):
        return QuarantineError('ROUTER_UNREACHABLE','Router request failed or timed out. A write may have taken effect; use Reconcile before retrying.')
    if isinstance(error,RuntimeError):
        return QuarantineError('ROUTER_AUTH_REJECTED','Router rejected authentication/session/API access. Check credentials and session; reconcile before retrying.')
    return QuarantineError('OPERATION_FAILED','Operation failed. Read-back reconciliation and the saved recovery snapshot are required.')


@contextmanager
def router_lease():
    owner=secrets.token_hex(16)
    conn=get_connection()
    try:
        conn.execute('BEGIN IMMEDIATE')
        row=conn.execute('SELECT expires_at FROM router_operation_lease WHERE id=1').fetchone()
        if row and row[0]>time.time():
            raise QuarantineError('BUSY','Another router operation is in progress. Wait and reconcile before retrying.')
        # Longer than the 120s plan lifetime plus bounded POST/read-back and
        # SQLite commit time, so another worker cannot take over mid-write.
        conn.execute('INSERT OR REPLACE INTO router_operation_lease VALUES (1,?,?)',(owner,time.time()+300))
        conn.commit()
    finally:
        conn.close()
    try:
        yield
    finally:
        conn=get_connection()
        try:
            conn.execute('DELETE FROM router_operation_lease WHERE id=1 AND owner=?',(owner,));conn.commit()
        finally: conn.close()


def get_state(device_id):
    conn=get_connection()
    try:
        row=conn.execute('SELECT * FROM router_quarantines WHERE device_id=?',(device_id,)).fetchone()
        if not row:
            return {'state':'NOT_REQUESTED','has_ownership':False,'verified_enforced':None,'verified_at':None,'message':'No verified LIVE quarantine has been requested.'}
        result=dict(row)
        indices=sorted({item['index'] for item in json.loads(row['ownership_json'])})
        result['ssid_indices']=indices
        result['scope_complete']=set(indices)=={'0','1','2','3'}
        result['has_ownership']=bool(indices)
        # Raw snapshots are available only through the authenticated recovery API.
        for key in ('before_xml','expected_xml','ownership_json'): result.pop(key,None)
        result['verified_enforced']=None if row['verified_enforced'] is None else bool(row['verified_enforced'])
        result['client_connected']=None if row['client_connected'] is None else bool(row['client_connected'])
        verified=datetime.fromisoformat(row['verified_at']) if row['verified_at'] else None
        result['verification_stale']=verified is None or (datetime.now()-verified).total_seconds()>30
        return result
    finally: conn.close()


def _record(device_id, mac, state, action, actor, operation_id, message, *, before=None, expected=None, ownership=None, error=None, enforced=None, verified=False, connected=None, details=None):
    audit_details=dict(details or {})
    if before is not None: audit_details['before_xml']=before.xml()
    if expected is not None: audit_details['expected_xml']=expected.xml()
    if ownership is not None: audit_details['ownership']=ownership
    conn=get_connection()
    try:
        conn.execute('BEGIN IMMEDIATE')
        conn.execute("""INSERT INTO router_quarantines
            (device_id,mac_address,state,action,actor,operation_id,before_xml,expected_xml,ownership_json,error_code,message,verified_enforced,verified_at,client_connected,updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(device_id) DO UPDATE SET state=excluded.state,action=excluded.action,actor=excluded.actor,
                operation_id=excluded.operation_id,before_xml=COALESCE(excluded.before_xml,router_quarantines.before_xml),
                expected_xml=COALESCE(excluded.expected_xml,router_quarantines.expected_xml),
                ownership_json=CASE WHEN ? THEN excluded.ownership_json ELSE router_quarantines.ownership_json END,
                error_code=excluded.error_code,message=excluded.message,verified_enforced=excluded.verified_enforced,
                verified_at=excluded.verified_at,client_connected=excluded.client_connected,updated_at=excluded.updated_at
            """,(device_id,mac,state,action,actor,operation_id,before.xml() if before else None,
                 expected.xml() if expected else None,json.dumps(ownership or []),error,message,
                 enforced,now_text() if verified else None,connected,now_text(),ownership is not None))
        conn.execute('INSERT INTO router_quarantine_audit (operation_id,device_id,mac_address,action,state,actor,message,details_json,timestamp) VALUES (?,?,?,?,?,?,?,?,?)',
                     (operation_id,device_id,mac,action,state,actor,message,json.dumps(audit_details),now_text()))
        conn.commit()
    finally: conn.close()


def _row(device_id):
    conn=get_connection()
    try:
        row=conn.execute('SELECT * FROM router_quarantines WHERE device_id=?',(device_id,)).fetchone()
        return dict(row) if row else None
    finally: conn.close()


def capabilities(*, dashboard=False):
    client=new_client()
    try:
        report,_=client.probe_quarantine_capabilities()
        report.update(writes_enabled=config.ROUTER_WRITES_ENABLED,protection_mode=config.PROTECTION_MODE,
                      recovery_confirmed=config.RECOVERY_CONFIRMED,auto_quarantine=False)
        if dashboard:
            from router import manual_mode
            report.update(protection_mode=manual_mode.get_mode(),writes_enabled=manual_mode.get_mode()=='LIVE',
                          release_available_in_demo=True,timed_recovery_used=False)
        return report
    except Exception as error: raise _safe_error(error)
    finally: client.close()


def prepare(device_id, action, mac, indices, allow_enable, actor_session, requester_ip=None, *, dashboard=False):
    if action not in ('quarantine','release','recover'):
        raise QuarantineError('INVALID_ACTION','Use quarantine, release or recover.')
    from router import manual_mode
    from router.write_safety import locked
    if dashboard and action=='quarantine':manual_mode.require_block_mode()
    prepared_generation=manual_mode.generation() if dashboard else None
    mac=normalize_mac(mac)
    validate_device(device_id,mac,requester_ip,blocking=action=='quarantine')
    client=new_client()
    try:
        report,before=client.probe_quarantine_capabilities()
        row=_row(device_id)
        if row and row['mac_address']!=mac:
            raise QuarantineError('IDENTITY_CHANGED','A managed quarantine belongs to a different MAC. Manual recovery is required.')
        if action=='quarantine':
            if row and row['ownership_json']!='[]' and row['state']!='RELEASED':
                ownership=json.loads(row['ownership_json'])
                if before.contains(mac,[o['index'] for o in ownership]):
                    _record(device_id,mac,'ACTIVE',action,'administrator',row['operation_id'],
                            'Existing managed deny rules verified; no additional router write.',enforced=True,verified=True)
                    return {'idempotent':True,'enforcement':get_state(device_id)}
                raise QuarantineError('RECOVERY_REQUIRED','A previous operation has unresolved ownership. Reconcile or recover it first.')
            after,ownership=plan_block(before,mac,indices,allow_enable is True)
            validate_device(device_id,mac,requester_ip,client.get_connected_wifi_devices(),indices=indices,identity_session=actor_session)
            if dashboard:validate_scope(client,indices)
        else:
            if row and row['state']=='RELEASED':
                prior=json.loads(row['ownership_json'])
                if any(before.ssids[o['index']].findtext('WifiMacFilterStatus')=='1' or
                       any((before.ssids[o['index']].findtext(f'WifiMacFilterMac{j}') or '').upper()==mac for j in range(10)) for o in prior):
                    raise QuarantineError('EXTERNAL_RULE','Router settings changed after release. No external rule will be removed.')
                _record(device_id,mac,'RELEASED',action,'administrator',row['operation_id'],
                        'Owned MAC remains absent on a fresh router read; no configuration write.',enforced=False,verified=True)
                return {'idempotent':True,'enforcement':get_state(device_id)}
            if not row or not row['ownership_json'] or row['ownership_json']=='[]':
                raise QuarantineError('NO_OWNERSHIP','NetGuardian has no owned router rule to release. It will not remove existing external rules.')
            ownership=json.loads(row['ownership_json'])
            after=plan_release(before,mac,ownership)
        ident=secrets.token_hex(24)
        conn=get_connection()
        try:
            conn.execute('INSERT INTO router_quarantine_plans (id,device_id,mac_address,actor_session,action,before_xml,after_xml,ownership_json,expires_at,control_channel,mode_generation) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                         (ident,device_id,mac,actor_session,action,before.xml(),after.xml(),json.dumps(ownership),time.time()+120,'dashboard' if dashboard else 'legacy',prepared_generation))
            conn.commit()
        finally: conn.close()
        return {'plan_id':ident,'device_id':device_id,'mac':mac,'action':action,'expires_in_seconds':120,
                'before':before.summary(),'after':after.summary(),'firmware':report['firmware'],
                'ssid_indices':[o['index'] for o in ownership],'expected_digest':after.digest(),
                'writes_enabled':not locked() and ((action!='quarantine' or manual_mode.get_mode()=='LIVE') if dashboard else config.ROUTER_WRITES_ENABLED),
                'writes_locked':locked(),
                'recovery_confirmed':True if dashboard else config.RECOVERY_CONFIRMED,
                'can_execute':not locked() and (action!='quarantine' or manual_mode.get_mode()=='LIVE') if dashboard else False,
                'protection_mode':manual_mode.get_mode() if dashboard else config.PROTECTION_MODE,
                'requires_separate_approval':True,'changes_mode':any(o['previous_mode']=='0' for o in ownership) and action=='quarantine',
                'recovery':'Release removes only this owned MAC and restores disabled mode only when no other rules depend on it. Wired desktop access must remain available. No restart/reboot is issued.'}
    except Exception as error: raise _safe_error(error)
    finally: client.close()


def execute(plan_id, actor_session, requester_ip=None, *, dashboard=False, confirmation=None):
    with router_lease():
        conn=get_connection()
        try:
            row=conn.execute('SELECT * FROM router_quarantine_plans WHERE id=? AND actor_session=?',(plan_id,actor_session)).fetchone()
            if row is None: raise QuarantineError('PLAN_NOT_FOUND','Prepare a plan in your authenticated administrator session first.')
            plan=dict(row)
            if dashboard != (plan['control_channel']=='dashboard'):
                raise QuarantineError('PLAN_CHANNEL_MISMATCH','Prepare this operation through the authenticated dashboard.')
            if dashboard:
                expected=dict(device_id=plan['device_id'],mac=plan['mac_address'],
                              ssid_indices=[o['index'] for o in json.loads(plan['ownership_json'])],
                              expected_digest=FilterSnapshot(plan['after_xml']).digest())
                if confirmation!=expected:
                    raise QuarantineError('TARGET_CONFIRMATION_MISMATCH','Selected device, MAC, scope or payload differs from the confirmed plan. Nothing was written; prepare again.')
            if plan['consumed']:
                # Repeated HTTP submissions cannot cause a second POST.
                state=_row(plan['device_id'])
                if state and state['operation_id']==plan_id: return get_state(plan['device_id'])
                raise QuarantineError('PLAN_USED','This plan was already used; reconcile before preparing another.')
            if plan['expires_at']<time.time(): raise QuarantineError('PLAN_EXPIRED','Plan expired. Refresh router state and prepare again.')
        finally: conn.close()
        before=FilterSnapshot(plan['before_xml']);after=FilterSnapshot(plan['after_xml'])
        token=None
        if dashboard:
            from router import manual_mode
            token=manual_mode.grant(plan['action'],plan['mac_address'],before,after,actor_session,plan['expires_at'],plan['mode_generation'])
        permit=WritePermit(plan_id,plan['mac_address'],before.digest(),after.digest(),plan['expires_at'],token,
                           plan['action'],tuple(o['index'] for o in json.loads(plan['ownership_json'])),plan['device_id'])
        permit.validate(before,after) # No state changes or router writes before separate approval gates.
        validate_device(plan['device_id'],plan['mac_address'],requester_ip,blocking=plan['action']=='quarantine')
        managed=_row(plan['device_id'])
        if managed and managed['ownership_json']!='[]' and managed['state']!='RELEASED' and plan['action']=='quarantine':
            raise QuarantineError('ALREADY_MANAGED','A different operation already owns this quarantine. Reconcile it; its recovery metadata will not be overwritten.')
        if plan['action']!='quarantine' and (not managed or managed['mac_address']!=plan['mac_address'] or
                                           json.loads(managed['ownership_json'])!=json.loads(plan['ownership_json'])):
            raise QuarantineError('OWNERSHIP_CHANGED','Managed rule ownership changed since the plan was prepared. Prepare a new recovery plan.')
        conn=get_connection()
        try:
            conn.execute('UPDATE router_quarantine_plans SET consumed=1 WHERE id=?',(plan_id,));conn.commit()
        finally: conn.close()
        device=plan['device_id'];mac=plan['mac_address'];action=plan['action'];ownership=json.loads(plan['ownership_json'])
        # Persist recovery metadata BEFORE attempting a configuration POST.
        _record(device,mac,'REQUESTED',action,'administrator',plan_id,'Manually confirmed router operation requested.',
                before=before,expected=after,ownership=ownership)
        client=None
        attempted=False
        try:
            client=new_client()
            _,fresh=client.probe_quarantine_capabilities()
            if fresh.digest()!=before.digest():
                raise QuarantineError('CONCURRENT_CHANGE','Router filters changed since approval. No configuration was written; prepare a new plan.')
            if action=='quarantine':
                validate_device(device,mac,requester_ip,client.get_connected_wifi_devices(),indices=[o['index'] for o in ownership],identity_session=actor_session)
                if dashboard:validate_scope(client,[o['index'] for o in ownership])
            _record(device,mac,'APPLYING',action,'administrator',plan_id,'Submitting only the saved, scoped MAC-filter delta.')
            if before.digest()!=after.digest():
                attempted=True
                client.write_mac_filter(before,after,permit)
            verified=client.read_mac_filter()
            if verified.digest()!=after.digest():
                raise QuarantineError('VERIFICATION_FAILED','Router read-back differs from the expected complete settings. Enforcement is unknown; reconcile or recover.')
            active=action=='quarantine'
            connected=None
            try:
                connected=any(w['mac'].upper()==mac for w in client.get_connected_wifi_devices())
            except Exception: pass
            _record(device,mac,'ACTIVE' if active else 'RELEASED',action,'administrator',plan_id,
                    'Deny-list entry verified. Wi-Fi disconnection is a separate observation.' if active else 'Owned MAC rule removal and retained settings verified.',
                    enforced=active,verified=True,connected=connected)
            return get_state(device)
        except Exception as error:
            safe=_safe_error(error)
            definitely_not_sent=not attempted or safe.code in {'CONCURRENT_CHANGE','WRITES_DISABLED','NOT_AUTHORIZED','PLAN_CHANGED','LIVE_MODE_REQUIRED','MODE_CHANGED','GRANT_EXPIRED','INCIDENT_LOCKDOWN','TARGET_DELTA_MISMATCH'}
            _record(device,mac,'FAILED',action,'administrator',plan_id,safe.message,error=safe.code,
                    ownership=[] if action=='quarantine' and definitely_not_sent else None)
            # Never blindly restore an old list after an uncertain write. A
            # separately confirmed recovery plan merges only our owned delta.
            return get_state(device)
        finally:
            if client: client.close()


def reconcile(device_id, requester_ip=None):
    with router_lease():
        row=_row(device_id)
        if not row: raise QuarantineError('NOT_REQUESTED','There is no LIVE operation to reconcile.')
        mac=row['mac_address'];ownership=json.loads(row['ownership_json'])
        validate_device(device_id,mac,requester_ip,blocking=False)
        client=new_client()
        try:
            _,snapshot=client.probe_quarantine_capabilities()
            indices=[o['index'] for o in ownership]
            if not indices: raise QuarantineError('NO_OWNERSHIP','No managed rule ownership exists.')
            active=snapshot.contains(mac,indices)
            absent=all(not any((snapshot.ssids[i].findtext(f'WifiMacFilterMac{j}') or '').upper()==mac for j in range(10)) for i in indices)
            connected=any(w['mac'].upper()==mac for w in client.get_connected_wifi_devices())
            conflicting_mode=any(snapshot.ssids[i].findtext('WifiMacFilterStatus')=='1' for i in indices)
            restoration_pending=absent and plan_release(snapshot,mac,ownership).digest()!=snapshot.digest() if not conflicting_mode else False
            state='FAILED' if conflicting_mode or restoration_pending else 'ACTIVE' if active else 'RELEASED' if absent else 'FAILED'
            _record(device_id,mac,state,'reconcile','administrator',row['operation_id'],
                    'External whitelist mode conflicts with the managed quarantine; review manually.' if conflicting_mode else
                    'Target MAC is absent, but owned filtering mode restoration is pending. Prepare Recovery to finish.' if restoration_pending else
                    'Read-only reconciliation: full target deny rule verified.' if active else 'Read-only reconciliation: target absent from owned scopes.' if absent else 'Partial rule or mode mismatch; recovery needs administrator review.',
                    enforced=None if conflicting_mode else True if active else False if absent else None,verified=True,connected=connected,
                    error=None if state!='FAILED' else 'PARTIAL_STATE')
            return get_state(device_id)
        except Exception as error:
            safe=_safe_error(error)
            _record(device_id,mac,'FAILED','reconcile','administrator',row['operation_id'],safe.message,error=safe.code)
            return get_state(device_id)
        finally: client.close()


def recovery_record(device_id):
    row=_row(device_id)
    if not row: raise QuarantineError('NOT_REQUESTED','No recovery snapshot exists.')
    conn=get_connection()
    try:
        audit=[dict(r) for r in conn.execute('SELECT * FROM router_quarantine_audit WHERE device_id=? ORDER BY id',(device_id,))]
    finally: conn.close()
    return {'device_id':device_id,'mac':row['mac_address'],'state':row['state'],'before_xml':row['before_xml'],
            'expected_xml':row['expected_xml'],'ownership':json.loads(row['ownership_json']),'audit':audit,
            'warning':'Do not replay the entire old snapshot over later router edits. Use a fresh recover plan to remove only this owned MAC.'}
