"""Evidence-gated incident closure. Never deletes the marker or writes to a router.

Hardware observations are explicit administrator attestations, not inferred from
MAC-filter read-back. They must accompany post-incident audited wire operations.
Every process still starts in DEMO and requires a new administrator mode approval.
"""
import hashlib
import hmac
import json
import time
from datetime import datetime

import config
from database.db import get_connection
from router.mac_filter import FilterSnapshot, QuarantineError, normalize_mac

OBSERVATIONS = ('target_denied', 'non_targets_unaffected', 'wired_management_unaffected',
                'target_reconnected_after_release', 'original_settings_restored')


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def _signature(value):
    return hmac.new(str(config.SECRET_KEY).encode(), _canonical(value), hashlib.sha256).hexdigest()


def _path():
    from router.write_safety import LOCK_FILE
    return LOCK_FILE.with_name(LOCK_FILE.name + '.closure.json')


def _marker():
    from router.write_safety import LOCK_FILE
    return hashlib.sha256(LOCK_FILE.read_bytes()).hexdigest()


def _evidence(block_id, release_id):
    conn = get_connection()
    try:
        plans = []
        audits = []
        for operation in (block_id, release_id):
            row = conn.execute('SELECT * FROM router_quarantine_plans WHERE id=?', (operation,)).fetchone()
            if not row:
                raise QuarantineError('HARDWARE_EVIDENCE_REQUIRED', 'Both post-incident hardware operation IDs must exist in the router audit journal.')
            plans.append(dict(row))
            audits.append([dict(r) for r in conn.execute(
                'SELECT * FROM router_quarantine_audit WHERE operation_id=? ORDER BY id', (operation,))])
        return plans, audits
    finally:
        conn.close()


def approved_record():
    """Fail closed on missing, changed, corrupt or unauthenticated evidence."""
    try:
        if config.AUTO_QUARANTINE is not False:
            return None
        envelope = json.loads(_path().read_text(encoding='utf-8'))
        record = envelope['record']
        if not hmac.compare_digest(envelope['signature'], _signature(record)):
            return None
        from router.write_safety import LOCK_FILE
        if (record['marker_digest'] != _marker() or record['version'] != 1 or
                record['marker_mtime_ns'] != LOCK_FILE.stat().st_mtime_ns):
            return None
        evidence = _evidence(record['block_operation_id'], record['release_operation_id'])
        # Later read-only reconciliation may append legitimate audit rows. Bind
        # the approval to its exact evidence rows without freezing the journal.
        evidence = (evidence[0], [[e for e in events if e['id'] in ids]
                                for events, ids in zip(evidence[1], record['audit_ids'])])
        if hashlib.sha256(_canonical(evidence)).hexdigest() != record['audit_digest']:
            return None
        return record
    except (OSError, ValueError, KeyError, TypeError, QuarantineError):
        return None
    except Exception:
        # Unavailable audit storage must never permit a physical write.
        return None


def close_incident(data, actor):
    from router.write_safety import LOCK_FILE
    from router.incident_review import verify_read_only
    if not LOCK_FILE.exists():
        raise QuarantineError('INCIDENT_MARKER_MISSING', 'Restore and review the persistent incident marker; closure cannot recreate or bypass it.')
    if not isinstance(data, dict) or data.get('confirmed') is not True:
        raise QuarantineError('CLOSURE_CONFIRMATION_REQUIRED', 'Explicit incident-closure approval is required.')
    if config.AUTO_QUARANTINE is not False:
        raise QuarantineError('AUTOMATIC_PHYSICAL_DISABLED_REQUIRED', 'Automatic physical quarantine must remain disabled.')
    cause = data.get('root_cause')
    approval = data.get('hardware_test_approval')
    if not isinstance(cause, str) or len(cause.strip()) < 30 or 'unconfirmed' in cause.lower():
        raise QuarantineError('CAUSE_UNRESOLVED', 'Record the established cause and corrective evidence before incident closure.')
    if not isinstance(approval, str) or len(approval.strip()) < 20:
        raise QuarantineError('TEST_APPROVAL_REQUIRED', 'Provide the separate, specific hardware-test approval reference; closure is not test authorization.')
    if not isinstance(data.get('observations'), dict) or any(data['observations'].get(key) is not True for key in OBSERVATIONS):
        raise QuarantineError('HARDWARE_OBSERVATIONS_REQUIRED', 'Confirm target denial, non-target and wired connectivity, target reconnection and full restoration from the separately approved test.')
    block_id, release_id = data.get('block_operation_id'), data.get('release_operation_id')
    if not all(isinstance(v, str) and v for v in (block_id, release_id)) or block_id == release_id:
        raise QuarantineError('HARDWARE_EVIDENCE_REQUIRED', 'Distinct audited hardware block and release operation IDs are required.')
    plans, audits = _evidence(block_id, release_id)
    block, release = plans
    if (block['action'] != 'quarantine' or release['action'] not in ('release', 'recover') or
            (block['device_id'], block['mac_address']) != (release['device_id'], release['mac_address'])):
        raise QuarantineError('HARDWARE_IDENTITY_MISMATCH', 'Hardware block and release must belong to the same verified device and MAC.')
    marker_time = LOCK_FILE.stat().st_mtime
    marker_digest = _marker()
    for plan, events, terminal in zip(plans, audits, ('ACTIVE', 'RELEASED')):
        transports = [e for e in events if e['actor'] == 'transport']
        completed = [e for e in events if e['state'] == terminal]
        if (not plan['consumed'] or not transports or not completed or
                any(datetime.fromisoformat(e['timestamp']).timestamp() <= marker_time for e in transports + completed)):
            raise QuarantineError('POST_INCIDENT_TEST_REQUIRED', 'A new separately approved hardware test with captured wire payloads and verified ACTIVE/RELEASED results is required. Historical tests cannot close this incident.')
        if any(e['device_id'] != plan['device_id'] or e['mac_address'] != plan['mac_address'] for e in completed):
            raise QuarantineError('HARDWARE_IDENTITY_MISMATCH', 'Verified hardware result belongs to a different identity.')
        expected = FilterSnapshot(plan['after_xml'])
        for event in transports:
            details = json.loads(event['details_json'])
            if (event['device_id'] != plan['device_id'] or normalize_mac(event['mac_address']) != plan['mac_address'] or
                    FilterSnapshot(details.get('wire_xml', '')).digest() != expected.digest()):
                raise QuarantineError('HARDWARE_IDENTITY_MISMATCH', 'Captured hardware XML does not match the approved device and payload.')
    if min(datetime.fromisoformat(e['timestamp']).timestamp() for e in audits[1]) < max(datetime.fromisoformat(e['timestamp']).timestamp() for e in audits[0]):
        raise QuarantineError('HARDWARE_SEQUENCE_INVALID', 'The verified release must follow the approved block.')
    baseline, blocked, restored = (FilterSnapshot(block['before_xml']), FilterSnapshot(block['after_xml']),
                                   FilterSnapshot(release['after_xml']))
    ownership = json.loads(block['ownership_json'])
    indices = sorted(o['index'] for o in ownership)
    from router.mac_filter import plan_release, validate_target_delta
    # The wire delta must target only this MAC, including preserved foreign rules.
    validate_target_delta(baseline, blocked, block['mac_address'], 'quarantine', tuple(indices))
    if (FilterSnapshot(release['before_xml']).digest() != blocked.digest() or
            plan_release(blocked, block['mac_address'], ownership).digest() != restored.digest() or
            restored.digest() != baseline.digest()):
        raise QuarantineError('RESTORATION_UNVERIFIED', 'Hardware test must verify exact restoration and preserve all unrelated settings.')
    report = verify_read_only()
    target = block['device_id']
    non_targets = data.get('non_target_device_ids')
    if (not isinstance(non_targets, list) or not non_targets or any(type(i) is not int or i == target for i in non_targets) or
            len(set(non_targets)) != len(non_targets)):
        raise QuarantineError('NON_TARGET_EVIDENCE_REQUIRED', 'Identify distinct non-target devices observed throughout the approved hardware test.')
    reviews = {r.get('device_id'): r for r in report.get('identity_reviews', [])}
    if (report.get('read_error') or report.get('filter_digest') != restored.digest() or
            report.get('enabled_ssid_indices') != indices or not reviews.get(target, {}).get('eligible') or
            not report.get('management_route', {}).get('wired_route_identified') or
            any(i not in reviews for i in non_targets) or report.get('saved_plan_identity_mismatches')):
        raise QuarantineError('FRESH_VERIFICATION_FAILED', 'Fresh router reads must confirm restoration, current stable target identity, non-target presence, sole SSID and wired management route.')
    if _marker()!=marker_digest or LOCK_FILE.stat().st_mtime!=marker_time:
        raise QuarantineError('INCIDENT_CHANGED', 'Incident marker changed during verification. Review the current incident.')
    record = dict(version=1, actor=actor, closed_at=time.time(), marker_digest=marker_digest,
                  marker_mtime_ns=LOCK_FILE.stat().st_mtime_ns,
                  block_operation_id=block_id, release_operation_id=release_id,
                  audit_digest=hashlib.sha256(_canonical((plans, audits))).hexdigest(),
                  audit_ids=[[e['id'] for e in events] for events in audits],
                  root_cause=cause.strip(), hardware_test_approval=approval.strip(),
                  observations={k: True for k in OBSERVATIONS}, non_target_device_ids=non_targets,
                  target_device_id=target, target_mac=block['mac_address'], ssid_indices=indices,
                  firmware=report['firmware'], restored_digest=restored.digest())
    # Exclusive create preserves earlier approval evidence instead of overwriting it.
    try:
        with _path().open('x', encoding='utf-8') as handle:
            json.dump(dict(record=record, signature=_signature(record)), handle, indent=2)
            handle.flush()
            import os
            os.fsync(handle.fileno())
    except FileExistsError:
        raise QuarantineError('CLOSURE_RECORD_EXISTS', 'A closure record already exists. It will not be overwritten; review its integrity locally.') from None
    return dict(status='success', message='Incident closure recorded; marker retained. Mode remains DEMO. Separately approve manual LIVE for this runtime.', writes_locked=False)
