"""Background integration of capture evidence and eligible behavioral history."""
import logging
import threading
from datetime import datetime

from database.db import get_connection
from database.models import get_all_devices, is_local_device_ip
from analytics.collection_schedule import get_safe_completed_window_end
from analytics.eligibility_collector import collect_eligible_observation
from analytics.capture_heartbeat import assess_heartbeat_window
from analytics.capture_sessions_v2 import assess_session_transitions_v2, record_session_heartbeat_v2
from capture.heartbeat_bridge import heartbeat_status_for_snapshot
from capture.heartbeat_reporter import CaptureHeartbeatReporter

_stop = threading.Event()
_thread = None
_lock = threading.Lock()
state = {"running": False, "last_cycle": None, "last_error": None, "stored": 0}


def collect_cycle(now=None):
    from capture import packet_capture as capture
    now = now or datetime.now()
    snapshot = capture.get_capture_health()
    reporter.report(snapshot, recorded_at=now)
    end = get_safe_completed_window_end(now=now)
    conn = get_connection()
    try:
        status = heartbeat_status_for_snapshot(snapshot)
        session_id = capture.capture_session_id
        if session_id and status:
            record_session_heartbeat_v2(conn, session_id, now, status)
            conn.commit()
        coverage = assess_heartbeat_window(conn, end)
        transitions = assess_session_transitions_v2(conn, end)
        stored = 0
        if coverage["heartbeat_candidate"] and transitions["transition_free"]:
            for dev in get_all_devices():
                # Learn only from approved devices with no active anomaly.
                if not dev["trusted"] or dev["status"] == "quarantined" or not is_local_device_ip(dev["ip_address"]):
                    continue
                if conn.execute("SELECT 1 FROM alerts WHERE device_id=? AND status='open' AND alert_type != 'unknown_device' LIMIT 1", (dev["id"],)).fetchone():
                    continue
                result = collect_eligible_observation(conn, conn, dev["id"], end, now=now)
                stored += int(result.get("stored", False))
            conn.commit()
        state.update(last_cycle=now.isoformat(timespec="seconds"), last_error=None, stored=stored)
        return dict(state)
    finally:
        conn.close()


reporter = CaptureHeartbeatReporter(get_connection)


def _run():
    state["running"] = True
    try:
        while not _stop.is_set():
            try:
                collect_cycle()
            except Exception as error:
                state["last_error"] = type(error).__name__
                logging.getLogger(__name__).exception("Analytics cycle failed")
            _stop.wait(5)
    finally:
        state["running"] = False


def start_analytics_monitor():
    global _thread, reporter
    with _lock:
        if _thread and _thread.is_alive():
            return
        reporter = CaptureHeartbeatReporter(get_connection)
        _stop.clear()
        _thread = threading.Thread(target=_run, name="NetGuardianAnalytics", daemon=True)
        _thread.start()


def stop_analytics_monitor():
    _stop.set()
    if _thread:
        _thread.join(timeout=3)
