"""Administrator-selected runtime mode. Every process starts in DEMO.

Mode changes perform no router I/O. Normal dashboard writes use one-shot,
scoped grants, separate from the privileged controlled-test CLI permissions.
"""
from contextlib import contextmanager
from datetime import datetime
import secrets
import threading
import time

from database.db import get_connection
from router.mac_filter import QuarantineError

_lock=threading.RLock()
_mode='DEMO'
# A new runtime cannot accidentally reuse a previous process's plan generation.
_generation=secrets.randbits(48)
_grants={}
_runtime_id=secrets.token_hex(16)


def get_mode():
    from router.write_safety import locked
    if locked():return 'DEMO'
    with _lock:return _mode


def generation():
    with _lock:return _generation


def status():
    conn=get_connection()
    try:
        pending=[dict(r) for r in conn.execute("SELECT device_id,state FROM router_quarantines WHERE ownership_json!='[]' AND state!='RELEASED' ORDER BY device_id")]
    finally:conn.close()
    with _lock:
        from router.write_safety import locked
        return dict(protection_mode=get_mode(),writes_locked=locked(),mode_generation=_generation,auto_quarantine=False,
                    release_available_in_demo=True,pending_managed_devices=pending,
                    startup_mode='DEMO',timed_recovery_used=False)


def switch(mode,actor):
    global _mode,_generation
    if mode not in ('DEMO','LIVE'):raise QuarantineError('INVALID_MODE','Choose DEMO or LIVE.')
    if mode=='LIVE':
        from router.write_safety import require_writes_allowed
        require_writes_allowed()
    with _lock:
        previous=_mode
        if mode!=previous:
            conn=get_connection()
            try:
                conn.execute('INSERT INTO protection_mode_audit (runtime_id,previous_mode,new_mode,actor,timestamp) VALUES (?,?,?,?,?)',
                             (_runtime_id,previous,mode,actor,datetime.now().isoformat(timespec='seconds')))
                conn.commit()
            finally:conn.close()
            _mode=mode;_generation+=1
        # Switching mode never applies or releases any router rule.
        return status()


def require_block_mode(expected_generation=None):
    from router.write_safety import require_writes_allowed
    require_writes_allowed()
    with _lock:
        if _mode!='LIVE':raise QuarantineError('LIVE_MODE_REQUIRED','New router quarantines require the administrator to select LIVE mode.')
        if expected_generation is not None and expected_generation!=_generation:
            raise QuarantineError('MODE_CHANGED','Mode changed after this plan was prepared. Prepare and confirm a new plan.')


def grant(action,mac,before,after,actor,expires_at,expected_generation):
    with _lock:
        if action=='quarantine':require_block_mode(expected_generation)
        token=secrets.token_hex(32)
        _grants[token]=dict(action=action,mac=mac,before=before.digest(),after=after.digest(),
                            actor=actor,expires_at=expires_at,generation=expected_generation,used=False)
        # Expired grant data is never needed for recovery; ownership is in SQLite.
        for key in list(_grants):
            if _grants[key]['expires_at']<time.time():del _grants[key]
        return token


def validate(token,permit,before,after):
    with _lock:
        item=_grants.get(token)
        if not item or item['used'] or item['expires_at']<time.time():
            raise QuarantineError('GRANT_EXPIRED','This administrator confirmation expired or was already used. Prepare a new plan.')
        if (item['mac'],item['before'],item['after'])!=(permit.mac,before.digest(),after.digest()):
            raise QuarantineError('PLAN_CHANGED','Router change does not match the confirmed administrator plan.')
        if permit.action and permit.action!=item['action']:
            raise QuarantineError('PLAN_CHANGED','Router action differs from the administrator grant.')
        if item['action']=='quarantine':require_block_mode(item['generation'])


@contextmanager
def authorized_wire_write(permit,before,after):
    # Serialize a mode switch with the actual POST, so switching to DEMO
    # prevents any not-yet-sent quarantine request from starting afterward.
    with _lock:
        from router.write_safety import require_writes_allowed
        require_writes_allowed()
        if permit.authorization_token:
            validate(permit.authorization_token,permit,before,after)
            _grants[permit.authorization_token]['used']=True
        else:permit.validate(before,after)
        yield
