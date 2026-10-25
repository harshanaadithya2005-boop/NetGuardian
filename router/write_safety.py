"""Persistent incident interlock, checked again at the physical write boundary."""
from pathlib import Path
from router.mac_filter import QuarantineError

LOCK_FILE = Path(__file__).with_name('LIVE_WRITES_DISABLED')

def locked():
    if not LOCK_FILE.exists():
        return False
    # Retain the incident marker permanently. Only authenticated, evidence-bound
    # closure can satisfy it; sign-in, mode switches and restarts cannot.
    from router.incident_closure import approved_record
    return approved_record() is None

def require_writes_allowed():
    if locked():
        raise QuarantineError('INCIDENT_LOCKDOWN', 'LIVE router writes are disabled for the identity incident. A separately approved recovery/test is required; no router settings were changed.')
