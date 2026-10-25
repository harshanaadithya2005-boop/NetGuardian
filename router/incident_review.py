"""Read-only incident assessment. Deliberately contains no unlock or write path."""
from datetime import datetime
from urllib.parse import urlsplit
import config
from database.db import get_connection
from router import write_safety
from router.mac_filter import FilterSnapshot, normalize_mac, QuarantineError
from response import router_quarantine as service


def status():
    from router.incident_closure import approved_record
    closure=approved_record()
    conn=get_connection()
    try:
        rows=[dict(r) for r in conn.execute('SELECT id,ip_address,mac_address,hostname,status FROM devices')]
        inconsistent=[]
        for plan in conn.execute('SELECT device_id,mac_address,action,after_xml,ownership_json FROM router_quarantine_plans'):
            if plan['action']!='quarantine':continue
            import json
            try:
                scope=[o['index'] for o in json.loads(plan['ownership_json'])]
                if not scope or not FilterSnapshot(plan['after_xml']).contains(plan['mac_address'],scope):
                    inconsistent.append(plan['device_id'])
            except (ValueError,KeyError,QuarantineError):inconsistent.append(plan['device_id'])
    finally:conn.close()
    groups={}
    for row in rows:
        name=str(row['hostname'] or '').strip().casefold()
        if name:groups.setdefault(name,[]).append(row)
    ambiguous={name:items for name,items in groups.items() if len({str(r['mac_address']).upper() for r in items})>1}
    return dict(writes_locked=write_safety.locked(),auto_quarantine=False,unlock_available=False,
                incident_marker_retained=write_safety.LOCK_FILE.exists(),closure_approved=bool(closure),
                root_cause=closure['root_cause'] if closure else 'UNCONFIRMED',ready_for_manual_live=bool(closure),
                saved_plan_identity_mismatches=sorted(set(inconsistent)),same_name_different_mac_records=ambiguous,
                checks=[dict(name='Persistent incident lock present',passed=write_safety.locked()),
                        dict(name='Automatic physical quarantine disabled',passed=config.AUTO_QUARANTINE is False),
                        dict(name='Saved quarantine plans target their bound MAC',passed=not inconsistent),
                        dict(name='Earlier non-target disconnection cause established',passed=bool(closure)),
                        dict(name='One non-management spare independently identified with stable MAC/SSID',passed=bool(closure)),
                        dict(name='Separate approval for a specific controlled hardware test',passed=bool(closure)),
                        dict(name='Successful target, non-target and wired-management hardware verification',passed=bool(closure)),
                        dict(name='Release and complete restoration verified in that approved test',passed=bool(closure)),
                        dict(name='Explicit incident-closure approval recorded',passed=bool(closure))])


def verify_read_only():
    report=status();report['verified_at']=datetime.now().isoformat(timespec='seconds')
    client=None;counts={'GET':0,'AUTH_POST':0,'CONFIG_POST':0}
    try:
        client=service.new_client()
        session=getattr(client,'session',None)
        if session is not None:
            original=session.request
            def guarded(method,url,**kwargs):
                parts=urlsplit(url);method=method.upper()
                if parts.hostname!='192.168.8.1':raise QuarantineError('READ_ONLY_GUARD','Unexpected router host; verification aborted.')
                if method=='GET':counts['GET']+=1
                elif method=='POST' and parts.path in {'/api/user/challenge_login','/api/user/authentication_login'}:counts['AUTH_POST']+=1
                else:raise QuarantineError('READ_ONLY_GUARD','Configuration requests are forbidden during incident verification.')
                return original(method,url,**kwargs)
            session.request=guarded
        capabilities,snapshot=client.probe_quarantine_capabilities()
        hosts=client.get_connected_wifi_devices();enabled=client.enabled_wifi_scopes()
        report.update(firmware=capabilities.get('firmware'),filters=snapshot.summary(),filter_digest=snapshot.digest(),
                      enabled_ssid_indices=enabled,clients=hosts,identity_reviews=[])
        try:
            from scapy.all import conf,get_if_hwaddr
            iface,source_ip,_=conf.route.route('192.168.8.1')
            adapter=conf.ifaces.dev_from_networkname(str(iface)).description
            report['management_route']=dict(source_ip=source_ip,mac=get_if_hwaddr(iface).upper(),adapter=adapter,
                                            wired_route_identified='ethernet' in adapter.lower())
            report['checks'].append(dict(name='Wired management route identified read-only (not a post-write connectivity test)',passed=report['management_route']['wired_route_identified']))
        except Exception:
            report['management_route']=dict(wired_route_identified=False)
            report['checks'].append(dict(name='Wired management route identified read-only',passed=False))
        conn=get_connection()
        try:devices=[dict(r) for r in conn.execute('SELECT * FROM devices')]
        finally:conn.close()
        for host in hosts:
            matches=[d for d in devices if str(d.get('mac_address') or '').strip().upper()==str(host.get('mac') or '').strip().upper()]
            review=dict(mac=host.get('mac'),ip=host.get('ip'),eligible=False)
            if len(matches)!=1:review['reason']='AMBIGUOUS_OR_UNKNOWN_INVENTORY_IDENTITY'
            else:
                review['device_id']=matches[0]['id']
                try:
                    service.validate_device(matches[0]['id'],normalize_mac(host['mac']),require_wifi=hosts,indices=enabled)
                    service.validate_scope(client,enabled)
                    review.update(eligible=True,reason='Current unique IP/MAC and sole enabled SSID matched; this is not hardware collateral-effect validation.')
                except Exception as error:
                    safe=service._safe_error(error);review.update(reason=safe.code,message=safe.message)
            report['identity_reviews'].append(review)
        report['checks'].append(dict(name='Exact router firmware and filter schema verified read-only',passed=True))
    except Exception as error:
        safe=service._safe_error(error);report['read_error']=dict(code=safe.code,message=safe.message)
        report['checks'].append(dict(name='Exact router firmware and filter schema verified read-only',passed=False))
    finally:
        if client is not None:client.close()
    report['requests']=counts
    report['configuration_writes']=0
    report['remaining_conditions']=[c['name'] for c in report['checks'] if not c['passed']]
    return report
