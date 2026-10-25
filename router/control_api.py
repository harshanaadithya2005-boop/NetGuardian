"""Loopback administrator sessions and CSRF-protected manual router controls."""
from collections import defaultdict, deque
from functools import wraps
import ipaddress
import secrets
import sqlite3
import threading
import time
from urllib.parse import urlsplit

from flask import Blueprint, jsonify, request, session
from werkzeug.security import check_password_hash

import config
from response import router_quarantine as service
from router.mac_filter import QuarantineError
from router import manual_mode

controls=Blueprint('router_controls',__name__)
_attempts=defaultdict(deque)
_attempt_lock=threading.Lock()


@controls.after_request
def private_control_responses(response):
    response.headers['Cache-Control']='no-store'
    response.headers['X-Content-Type-Options']='nosniff'
    return response


def _local_request():
    try:
        return ipaddress.ip_address(request.remote_addr).is_loopback and urlsplit('http://'+request.host).hostname in {'127.0.0.1','localhost','::1'}
    except (ValueError,TypeError): return False


def _csrf_valid():
    expected=session.get('csrf')
    supplied=request.headers.get('X-CSRF-Token','')
    return isinstance(expected,str) and secrets.compare_digest(expected,supplied)


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args,**kwargs):
        if not _local_request(): return jsonify(status='error',code='LOCAL_ONLY',message='Router administration is available only from the local management PC.'),403
        if not config.ADMIN_PASSWORD_HASH or not session.get('admin_session') or session.get('admin_until',0)<time.time():
            return jsonify(status='error',code='ADMIN_REQUIRED',message='Sign in with the configured NetGuardian administrator password.'),401
        if request.method!='GET' and not _csrf_valid():
            return jsonify(status='error',code='CSRF_REJECTED',message='Session protection expired. Sign in again and prepare a fresh plan.'),403
        return fn(*args,**kwargs)
    return wrapper


@controls.get('/api/router/incident')
@admin_required
def incident_status():
    from router.incident_review import status
    return jsonify(status())


@controls.post('/api/router/incident/verify')
@admin_required
def incident_verify():
    from router.incident_review import verify_read_only
    return jsonify(verify_read_only())


@controls.post('/api/router/incident/close')
@admin_required
def incident_close():
    from router.incident_closure import close_incident
    # This records approval only; never changes mode or performs router writes.
    with service.router_lease():
        try:
            return jsonify(close_incident(request.get_json(silent=True), 'Local authenticated administrator'))
        except QuarantineError:
            raise
        except Exception as error:
            raise service._safe_error(error) from None


@controls.errorhandler(QuarantineError)
def control_error(error):
    return jsonify(status='error',code=error.code,message=error.message),409


@controls.errorhandler(sqlite3.Error)
def journal_error(error):
    return jsonify(status='error',code='JOURNAL_UNAVAILABLE',message='Local audit/recovery storage is unavailable. Restore database access and reconcile router state before retrying.'),503


@controls.get('/api/admin/session')
def admin_session():
    if not _local_request(): return jsonify(status='error',message='Local access required.'),403
    session.setdefault('csrf',secrets.token_hex(32))
    return jsonify(csrf_token=session['csrf'],authenticated=bool(session.get('admin_session') and session.get('admin_until',0)>time.time()),
                   configured=bool(config.ADMIN_PASSWORD_HASH),writes_enabled=manual_mode.get_mode()=='LIVE',
                   recovery_confirmed=True,**manual_mode.status())


@controls.get('/api/protection-mode')
def protection_mode_status():
    return jsonify(manual_mode.status())


@controls.post('/api/protection-mode')
@admin_required
def change_protection_mode():
    data=request.get_json(silent=True)
    if not isinstance(data,dict) or data.get('confirmed') is not True:
        return jsonify(status='error',message='Explicit mode-switch confirmation is required.'),400
    result=manual_mode.switch(data.get('mode'),'Local authenticated administrator')
    return jsonify(status='success',message='Mode changed without any router write. Existing router rules require an explicit Release.',**result)


@controls.post('/api/admin/login')
def admin_login():
    if not _local_request(): return jsonify(status='error',message='Local access required.'),403
    if not _csrf_valid(): return jsonify(status='error',message='Refresh the administrator session before signing in.'),403
    if not config.ADMIN_PASSWORD_HASH:
        return jsonify(status='error',code='ADMIN_NOT_CONFIGURED',message='Configure NETGUARDIAN_ADMIN_PASSWORD_HASH locally. Router writes remain disabled.'),503
    data=request.get_json(silent=True)
    if not isinstance(data,dict) or not isinstance(data.get('password'),str) or len(data['password'])>256:
        return jsonify(status='error',message='An administrator password is required.'),400
    key=request.remote_addr
    with _attempt_lock:
        recent=_attempts[key]
        while recent and recent[0]<time.monotonic()-900: recent.popleft()
        if len(recent)>=5: return jsonify(status='error',message='Too many sign-in attempts. Wait 15 minutes.'),429
        recent.append(time.monotonic())
    try: valid=check_password_hash(config.ADMIN_PASSWORD_HASH,data['password'])
    except ValueError: valid=False
    if not valid: return jsonify(status='error',message='Administrator sign-in rejected.'),401
    with _attempt_lock: _attempts[key].clear()
    session.clear();session['csrf']=secrets.token_hex(32);session['admin_session']=secrets.token_hex(32);session['admin_until']=time.time()+900
    return jsonify(status='success',csrf_token=session['csrf'],message='Administrator session expires in 15 minutes.')


@controls.post('/api/admin/logout')
@admin_required
def admin_logout():
    session.clear()
    return jsonify(status='success')


@controls.get('/api/router/capabilities')
@admin_required
def router_capabilities():
    return jsonify(service.capabilities(dashboard=True))


@controls.get('/api/device/<int:device_id>/enforcement')
def enforcement_status(device_id):
    # Sanitized status only; credentials, snapshots and audit remain private.
    return jsonify(service.get_state(device_id))


@controls.post('/api/device/<int:device_id>/router-quarantine/plan')
@admin_required
def prepare_plan(device_id):
    data=request.get_json(silent=True)
    if not isinstance(data,dict) or type(data.get('allow_enable',False)) is not bool:
        return jsonify(status='error',message='A structured plan and explicit boolean mode-change consent are required.'),400
    return jsonify(service.prepare(device_id,data.get('action'),data.get('mac'),data.get('ssid_indices'),
                                   data.get('allow_enable',False),session['admin_session'],request.remote_addr,dashboard=True))


@controls.post('/api/device/<int:device_id>/router-identity/verify')
@admin_required
def confirm_wifi_identity(device_id):
    from router.wifi_identity import confirm
    with service.router_lease():
        return jsonify(confirm(device_id, request.get_json(silent=True), session['admin_session'], request.remote_addr))


@controls.post('/api/router/quarantine/execute')
@admin_required
def execute_plan():
    data=request.get_json(silent=True)
    if not isinstance(data,dict) or data.get('confirmed') is not True or not isinstance(data.get('plan_id'),str):
        return jsonify(status='error',message='Explicit confirmation of the prepared plan is required.'),400
    confirmation={key:data.get(key) for key in ('device_id','mac','ssid_indices','expected_digest')}
    result=service.execute(data['plan_id'],session['admin_session'],request.remote_addr,dashboard=True,confirmation=confirmation)
    return jsonify(status='error' if result['state']=='FAILED' else 'success',enforcement=result,message=result['message']),409 if result['state']=='FAILED' else 200


@controls.post('/api/device/<int:device_id>/router-quarantine/reconcile')
@admin_required
def reconcile(device_id):
    result=service.reconcile(device_id,request.remote_addr)
    return jsonify(enforcement=result,message=result['message'])


@controls.get('/api/device/<int:device_id>/router-quarantine/recovery')
@admin_required
def recovery(device_id):
    response=jsonify(service.recovery_record(device_id))
    response.headers['Cache-Control']='no-store'
    response.headers['Content-Disposition']=f'attachment; filename=netguardian-recovery-{device_id}.json'
    return response
