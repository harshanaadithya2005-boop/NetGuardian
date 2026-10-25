import sys
from pathlib import Path

# Ensure project root is in sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import config
import ipaddress
from database.models import (
    get_all_devices,
    get_device_by_id,
    get_recent_traffic,
    get_recent_dns_queries,
    get_recent_tcp_syn_traffic,
    update_device_risk,
    create_alert
)
from detection.unknown_device import check_unknown_device
from detection.port_scan import check_port_scan
from detection.dns_anomaly import check_dns_anomaly
from detection.behaviour_drift import check_behaviour_drift_for_device
from response.quarantine import quarantine_device


# Risk Scoring Weights (Proposal Section 8.3)
RISK_SCORES = config.RISK_WEIGHTS


def calculate_risk(detections):
    """
    Original function from Member 2:
    Sum the fixed weights of all detected indicators, capped at 100.
    """
    score = config.RISK_BASELINE
    for detection in set(detections):
        score += RISK_SCORES.get(detection, 0)
    return max(0, min(score, 100))


def get_risk_level(score):
    """
    Original function from Member 2 updated to match Proposal Section 8.3:
    - 0-39: LOW (Green - Normal)
    - 40-69: MEDIUM (Amber - Suspicious)
    - 70-100: HIGH (Red - Critical)
    """
    if score < config.RISK_THRESHOLD_MEDIUM:
        return "LOW"
    elif score < config.RISK_THRESHOLD_HIGH:
        return "MEDIUM"
    else:
        return "HIGH"


def evaluate_device_risk(device_or_id, auto_quarantine=False, *, policy_router=None):
    """Evaluate observed packets; automatic response can only make safe decisions."""
    from datetime import datetime, timedelta
    from detection.connection_patterns import check_connection_patterns
    from detection.evidence_store import save_evaluation,evidence_fingerprint
    from database.db import get_connection,is_isolated
    from response import policy
    if policy_router is not None and not is_isolated():raise ValueError('Mock policy routers require isolated replay context')
    device=device_or_id if isinstance(device_or_id,dict) else get_device_by_id(device_or_id)
    if not device:return None
    device_id=device['id'];ip=device.get('ip_address');now=datetime.now()
    traffic=get_recent_traffic(limit=50000,device_id=device_id,minutes=5,is_simulated=False)
    syn=get_recent_tcp_syn_traffic(device_id=device_id,minutes=config.PORT_SCAN_WINDOW_MINUTES,limit=5000)
    dns=get_recent_dns_queries(device_id=device_id,minutes=config.DNS_WINDOW_MINUTES,limit=5000)
    raw=[]
    if not device.get('trusted'):
        unknown=check_unknown_device(ip)
        if unknown.get('detected'):raw.append((dict(unknown,type='unknown_device'),[],30))
    port=check_port_scan(syn,source_ip=ip)
    if port.get('detected'):raw.append((dict(port,type='port_scan'),syn,config.PORT_SCAN_WINDOW_MINUTES))
    from analytics.learned_baseline import get_learned_baseline
    import sqlite3
    try:dns_profile,_=get_learned_baseline(device_id,device.get('mac_address'),now-timedelta(minutes=5))
    except sqlite3.OperationalError:dns_profile=None # Compatibility with isolated legacy test schemas.
    domain=check_dns_anomaly(dns,source_ip=ip,baseline_query_rate=dns_profile['normal_dns_rate']/5 if dns_profile else None)
    if domain.get('detected'):raw.append((dict(domain,type='dns_anomaly'),dns,config.DNS_WINDOW_MINUTES))
    drift=check_behaviour_drift_for_device(device_id,recent_traffic=traffic)
    if drift.get('detected'):
        drift_rows=traffic
        metrics=drift.get('metrics',{})
        if metrics.get('window_start') and metrics.get('window_end'):
            drift_rows=[r for r in get_recent_traffic(limit=50000,device_id=device_id,minutes=20,is_simulated=False)
                        if metrics['window_start']<=r['timestamp']<metrics['window_end']]
        if drift.get('traffic_spike'):raw.append((dict(drift,type='traffic_spike'),drift_rows,5))
        if drift.get('drift_score',0)>=50:raw.append((dict(drift,type='behaviour_drift'),drift_rows,5))
    for pattern in check_connection_patterns(traffic,ip):
        if pattern['detected']:
            pattern_ids=set(pattern['packet_ids'])
            raw.append((pattern,[r for r in traffic if r.get('id') in pattern_ids],5))
    detections=[];contributions={};source='ISOLATED_PACKET_REPLAY' if is_isolated() else 'LIVE_CAPTURE'
    for raw_result,rows,minutes in raw:
        kind=raw_result['type'];records=[r for r in rows if r.get('source_ip')==ip and not r.get('is_simulated')]
        times=[]
        for r in records:
            try:
                t=datetime.fromisoformat(r['timestamp'])
                if t<=now:times.append(t)
            except (KeyError,TypeError,ValueError):pass
        observed=max(times) if times else now
        confidence=raw_result.get('confidence',.85 if kind=='port_scan' else .85 if kind in {'traffic_spike','behaviour_drift'} else .5)
        if kind=='dns_anomaly':
            burst=raw_result.get('query_count',0)>=raw_result.get('query_threshold',config.DNS_QUERY_RATE_THRESHOLD) and raw_result.get('distinct_domains',0)>=20
            confidence=.85 if burst else .7 if raw_result.get('anomaly_count',0)>=3 and raw_result.get('distinct_domains',0)>=3 else .45
        evidence=dict(raw_result,packet_ids=[r['id'] for r in records if 'id' in r],packet_count=len(records),
                      destination_ips=sorted({str(r.get('destination_ip')) for r in records if r.get('destination_ip')}),
                      window_start=(min(times) if times else now-timedelta(minutes=minutes)).isoformat(timespec='seconds'),
                      window_end=observed.isoformat(timespec='seconds'),window_minutes=minutes,
                      query_truncated=len(records)>=5000 if kind in {'port_scan','dns_anomaly'} else len(records)>=50000)
        if evidence['query_truncated']:confidence=min(confidence,.6)
        group='identity' if kind=='unknown_device' else 'volume' if kind in {'traffic_spike','sustained_flood'} else kind
        if kind=='behaviour_drift' and raw_result.get('breakdown'):
            # A drift made only of scan ports, DNS burst or volume adds no new incident.
            breakdown=raw_result['breakdown'];independent=breakdown.get('distinct_ips',{}).get('drift_pct',0)>0
            overlap=(port.get('detected') or domain.get('detected') or drift.get('traffic_spike'))
            if overlap and not independent:group='overlap'
        weight=config.RISK_WEIGHTS.get(kind,0)
        if group=='overlap':weight=0
        if group=='volume':
            other=max((d['risk_contribution'] for d in detections if d['incident_group']=='volume'),default=0)
            if other:
                if weight>other:
                    for d in detections:
                        if d['incident_group']=='volume':contributions[d['type']]=0;d['risk_contribution']=0
                else:weight=0
        contributions[kind]=weight
        detections.append(dict(device_id=device_id,ip_address=ip,mac_address=device.get('mac_address'),identity_confidence='INVENTORY_ONLY',
                               type=kind,timestamp=now.isoformat(timespec='seconds'),observed_at=observed.isoformat(timespec='seconds'),
                               expires_at=(observed+timedelta(minutes=minutes)).isoformat(timespec='seconds'),
                               severity=raw_result.get('severity','HIGH' if kind=='behaviour_drift' else 'MEDIUM'),confidence=confidence,
                               recommended_action='ADMINISTRATOR_REVIEW',incident_group=group,risk_contribution=weight,
                               source='INVENTORY_DISCOVERY' if kind=='unknown_device' and not is_isolated() else source,evidence=evidence,message=raw_result.get('message',kind.replace('_',' '))))
    # Behavioral aggregates of an already explained packet set are not a new incident.
    primary_ids=set().union(*(set(d['evidence']['packet_ids']) for d in detections if d['type'] not in {'unknown_device','traffic_spike','behaviour_drift'}))
    for d in detections:
        ids=set(d['evidence']['packet_ids'])
        if d['type'] in {'traffic_spike','behaviour_drift'} and ids and ids<=primary_ids:
            d['risk_contribution']=0;d['incident_group']='overlap';d['suppressed_reason']='Same packets already counted by primary detectors.';contributions[d['type']]=0
    kept=[]
    for d in sorted(detections,key=lambda row:row['risk_contribution'],reverse=True):
        ids=set(d['evidence']['packet_ids'])
        if not ids or not d['risk_contribution']:continue
        for earlier in kept:
            other=set(earlier['evidence']['packet_ids'])
            if len(ids&other)/len(ids|other)>=.9:
                d['risk_contribution']=0;d['incident_group']=earlier['incident_group'];d['suppressed_reason']='At least 90% overlapping packet evidence; counted once.';contributions[d['type']]=0;break
        if d['risk_contribution']:kept.append(d)
    from ai.ai_engine import explain_detection
    for detection in detections:detection['explanation']=explain_detection(detection)
    score=max(0,min(100,config.RISK_BASELINE+sum(contributions.values())))
    severity='CRITICAL' if score>=config.RISK_THRESHOLD_CRITICAL else get_risk_level(score)
    conn=get_connection()
    try:
        persistable=bool(conn.execute("SELECT 1 FROM sqlite_master WHERE name='detection_evidence'").fetchone() and conn.execute('SELECT 1 FROM devices WHERE id=?',(device_id,)).fetchone())
        for d in detections:
            handled=False
            if persistable:
                existing=conn.execute('SELECT a.status FROM detection_evidence e JOIN alerts a ON a.id=e.alert_id WHERE e.device_id=? AND e.detection_type=? AND e.fingerprint=? AND e.source=?',(device_id,d['type'],evidence_fingerprint(d),source)).fetchone()
                handled=bool(existing and existing['status'] in {'resolved','ignored'})
            if d['type']=='unknown_device' and d['evidence'].get('classification')!='newly_discovered':continue
            if not handled:
                alert_id=create_alert(device_id=device_id,alert_type=d['type'],risk_score=score,severity=d['severity'],description=d['message'],refresh_open=True)
                d['alert_id']=alert_id if type(alert_id) is int else None
    finally:conn.close()
    update_device_risk(device_id,score)
    result=dict(device_id=device_id,device_name=device.get('device_name') or device.get('hostname') or f'Device {device_id}',ip_address=ip,risk_score=score,risk_level=get_risk_level(score),severity=severity,
                confidence=min((d['confidence'] for d in detections if d['type']!='unknown_device'),default=0),
                indicators=[d['type'] for d in detections],detections=detections,contributions=contributions,
                baseline_risk=config.RISK_BASELINE,formula='clamp(baseline + sum(unique independent indicator contributions), 0, 100)',
                quarantined=device.get('status')=='quarantined',source=source,evaluated_at=now.isoformat(timespec='seconds'),
                explanation='; '.join(f"{d["type"]}: +{d["risk_contribution"]} ({d["message"]})" for d in detections) or 'No current detection indicators; baseline risk only.')
    if persistable:
        result=save_evaluation(device,result)
        result['response_decision']=policy.evaluate(device,result,router=policy_router)
    return result


def evaluate_all_devices(auto_quarantine=False):
    """
    Evaluate verified devices belonging to the monitored network.

    Exclude historical placeholder MAC identities while
    preserving real offline devices for risk evaluation.
    """

    devices = get_all_devices()
    evaluations = []

    local_network = ipaddress.ip_network(
        config.TARGET_NETWORK,
        strict=False
    )

    invalid_macs = {
        "",
        "AUTO-CAPTURED",
        "UNKNOWN",
        "00:00:00:00:00:00"
    }

    for dev in devices:
        ip_address = dev.get("ip_address")

        if not ip_address:
            continue

        # Exclude historical or unverified device identities.
        mac = str(
            dev.get("mac_address") or ""
        ).strip().upper()

        if mac in invalid_macs:
            continue

        try:
            device_ip = ipaddress.ip_address(ip_address)
        except (ValueError, TypeError):
            continue

        if device_ip not in local_network:
            continue

        result = evaluate_device_risk(
            dev,
            auto_quarantine=auto_quarantine
        )

        if result is not None:
            evaluations.append(result)

    return evaluations



if __name__ == "__main__":
    print("Testing Risk Engine:")
    sample_detections = ["unknown_device", "port_scan", "dns_anomaly"]
    sample_score = calculate_risk(sample_detections)
    print(f"Detections: {sample_detections}")
    print(f"Calculated Score: {sample_score}/100")
    print(f"Risk Level: {get_risk_level(sample_score)}")
