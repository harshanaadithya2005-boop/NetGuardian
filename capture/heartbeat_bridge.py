
"""
NetGuardian - Capture Health to Heartbeat Bridge

Translates real worker-health snapshots into
heartbeat records.

The caller supplies a SQLite connection.
No automatic threads or production database writes.
"""

from datetime import datetime

from analytics.capture_heartbeat import record_heartbeat


def heartbeat_status_for_snapshot(snapshot):
    """
    Return CAPTURING, ERROR, or None.

    None means the health evidence is not sufficient
    to record a healthy heartbeat.
    """

    if not isinstance(snapshot, dict):
        raise TypeError("Health snapshot must be a dictionary")

    status = snapshot.get("status")
    worker_error = snapshot.get("worker_error")

    if worker_error is not None:
        return "ERROR"

    if status in {"ERROR", "WRITE_ERROR"}:
        return "ERROR"

    if (
        status == "CAPTURING"
        and snapshot.get("running") is True
        and snapshot.get("recent_successful_write") is True
        and snapshot.get("heartbeat_candidate") is True
    ):
        return "CAPTURING"

    return None



def persist_health_heartbeat(
    conn,
    snapshot,
    recorded_at=None,
    worker_name="packet_capture"
):
    """
    Store one heartbeat per worker per minute.

    ERROR has priority over CAPTURING within the
    same minute.

    A later healthy snapshot cannot erase an ERROR
    recorded during that minute.

    Caller controls the SQLite transaction.
    """

    moment = (
        datetime.now()
        if recorded_at is None
        else recorded_at
    )

    if not isinstance(moment, datetime):
        raise TypeError("recorded_at must be a datetime")

    if moment.tzinfo is not None:
        raise ValueError("Use local naive timestamps")

    status = heartbeat_status_for_snapshot(snapshot)

    if status is None:
        return {
            "status": "NOT_RECORDED",
            "inserted": False,
            "updated": False,
            "reason": snapshot.get("status")
        }

    minute = moment.replace(
        second=0,
        microsecond=0
    )

    inserted = record_heartbeat(
        conn=conn,
        recorded_at=minute,
        worker_name=worker_name,
        status=status
    )

    updated = False

    # If a healthy heartbeat already exists,
    # upgrade it to ERROR when a failure occurs.
    #
    # Never downgrade ERROR to CAPTURING.
    if status == "ERROR" and not inserted:
        cursor = conn.execute("""
            UPDATE capture_heartbeats
            SET status = 'ERROR'
            WHERE worker_name = ?
              AND recorded_at = ?
              AND status = 'CAPTURING'
        """, (
            worker_name.strip(),
            minute.isoformat(timespec="seconds")
        ))

        updated = cursor.rowcount == 1

    return {
        "status": status,
        "inserted": inserted,
        "updated": updated,
        "recorded_at": minute.isoformat(
            timespec="seconds"
        )
    }
