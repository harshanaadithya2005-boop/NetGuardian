"""Short-lived administrator-confirmed private Wi-Fi identities; no router writes.

The administrator reads MAC and IP independently from the target's Wi-Fi
settings. Matching a router hostname alone never creates a trusted binding.
Bindings are scoped to this process, database and authenticated admin session.
"""
import hashlib
import json
import threading
import time

from database.db import database_path, get_connection
from database.models import get_device_by_id
from router.mac_filter import normalize_mac, QuarantineError

_bindings = {}
_lock = threading.RLock()
TTL = 900


def _key(device_id, actor_session):
    return str(database_path().resolve()), device_id, actor_session


def lookup(device_id, mac, ip, hostname, indices, actor_session):
    if not actor_session or indices is None:
        return None
    with _lock:
        key = _key(device_id, actor_session)
        binding = _bindings.get(key)
        if binding and binding['expires_at'] <= time.time():
            del _bindings[key]
            return None
        if not binding:
            return None
        if (binding['mac'], binding['ip'], binding['hostname'], binding['ssid_indices']) != (
                mac, ip, hostname.strip().casefold(), sorted(indices)):
            # Once an observed identity changes, the old proof cannot revive.
            del _bindings[key]
            return None
        return dict(binding)


def confirm(device_id, data, actor_session, requester_ip):
    from response import router_quarantine as service
    if (not isinstance(data, dict) or data.get('confirmed') is not True or
            data.get('stable_mac_confirmed') is not True or data.get('non_management') is not True):
        raise QuarantineError('IDENTITY_CONFIRMATION_REQUIRED', 'Read this device’s Wi-Fi MAC and IP from its own settings and confirm a stable per-network address and non-management use.')
    mac = normalize_mac(data.get('mac'))
    indices = data.get('ssid_indices')
    if not isinstance(indices, list) or len(indices) != 1 or indices[0] not in ('0', '1', '2', '3'):
        raise QuarantineError('SSID_IDENTITY_UNVERIFIED', 'Select exactly the one enabled SSID scope.')
    # Validate database, duplicate identity and protected management devices
    # before making even a read-only router request.
    device = service.validate_device(device_id, mac, requester_ip)
    if not isinstance(data.get('ip'), str) or data['ip'].strip() != device['ip_address']:
        raise QuarantineError('IDENTITY_CHANGED', 'The IP read from the device does not match this inventory row. Refresh discovery; do not substitute another device’s MAC.')
    client = service.new_client()
    try:
        service.validate_scope(client, indices)
        hosts = client.get_connected_wifi_devices()
        try:
            service.validate_device(device_id, mac, requester_ip, require_wifi=hosts, indices=indices)
        except QuarantineError as error:
            # This specific error occurs only AFTER all live identity,
            # hostname, uniqueness and management checks have succeeded.
            if error.code != 'RANDOMIZED_IDENTITY_UNVERIFIED':
                raise
        host = next(w for w in hosts if str(w.get('mac', '')).upper() == mac and w.get('ip') == device['ip_address'])
        hostname = str(host.get('hostname') or '').strip().casefold()
        if not hostname:
            raise QuarantineError('IDENTITY_CHANGED', 'Router client identity is incomplete. Rediscover before confirming a private address.')
        current=get_device_by_id(device_id)
        identity_fields=('id','ip_address','mac_address','hostname')
        if not current or any(current.get(key)!=device.get(key) for key in identity_fields):
            raise QuarantineError('IDENTITY_CHANGED', 'Inventory changed during verification. Refresh and confirm again.')
        binding = dict(device_id=device_id, mac=mac, ip=device['ip_address'], hostname=hostname,
                       ssid_indices=sorted(indices), verified_at=time.time(), expires_at=time.time()+TTL)
        # Preserve the verification in the existing append-only router audit;
        # do not set ACTIVE or modify device/enforcement records.
        conn = get_connection()
        try:
            conn.execute('INSERT INTO router_quarantine_audit (operation_id,device_id,mac_address,action,state,actor,message,details_json,timestamp) VALUES (?,?,?,?,?,?,?,?,?)',
                         ('identity-'+hashlib.sha256((actor_session+str(time.time_ns())).encode()).hexdigest(),
                          device_id,mac,'verify_identity','IDENTITY_VERIFIED','administrator',
                          'Administrator independently confirmed target Wi-Fi settings; current router MAC/IP/SSID matched. No router write.',
                          json.dumps(binding),service.now_text()))
            conn.commit()
        finally:
            conn.close()
        with _lock:
            # Discard expired sessions so repeated logins do not grow memory.
            for key in list(_bindings):
                if _bindings[key]['expires_at'] <= time.time():
                    del _bindings[key]
            _bindings[_key(device_id, actor_session)] = binding
        return dict(status='success', device_id=device_id, mac=mac, ip=device['ip_address'],
                    ssid_indices=indices, expires_in_seconds=TTL,
                    message='Current Wi-Fi identity confirmed for this administrator session (up to 15 minutes). Prepare a new quarantine plan. No router settings changed.')
    except Exception as error:
        raise service._safe_error(error) from None
    finally:
        client.close()
