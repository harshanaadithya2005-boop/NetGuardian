
"""
NetGuardian - Capture Sessions V2

Session-aware capture worker history.

The caller supplies the SQLite connection.
No automatic capture, scheduling or production writes.

Designed for isolated validation before integration.
"""

from datetime import datetime, timedelta
from uuid import uuid4


def _timestamp(value):
    if not isinstance(value, datetime):
        raise TypeError("Timestamp must be datetime")

    if value.tzinfo is not None:
        raise ValueError("Use local naive timestamps")

    return value.isoformat(timespec="seconds")


def create_session_tables_v2(conn):
    """Create the isolated V2 session and heartbeat schema."""

    conn.execute("""
        CREATE TABLE IF NOT EXISTS capture_sessions_v2 (
            session_id TEXT PRIMARY KEY,
            worker_name TEXT NOT NULL,
            started_at TEXT NOT NULL,
            ended_at TEXT,
            end_reason TEXT,
            CHECK (
                ended_at IS NULL
                OR ended_at >= started_at
            )
        )
    """)

    # Only one open session for each worker name.
    conn.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS
        idx_capture_session_active_v2
        ON capture_sessions_v2(worker_name)
        WHERE ended_at IS NULL
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS capture_heartbeats_v2 (
            session_id TEXT NOT NULL,
            recorded_at TEXT NOT NULL,
            status TEXT NOT NULL
                CHECK(status IN ('CAPTURING', 'ERROR')),
            PRIMARY KEY(session_id, recorded_at),
            FOREIGN KEY(session_id)
                REFERENCES capture_sessions_v2(session_id)
        )
    """)


def start_capture_session_v2(
    conn,
    started_at,
    worker_name="packet_capture"
):
    """Create a new uniquely identified capture session."""

    timestamp = _timestamp(started_at)

    if not isinstance(worker_name, str) or not worker_name.strip():
        raise ValueError("Invalid worker name")

    session_id = uuid4().hex

    conn.execute("""
        INSERT INTO capture_sessions_v2
            (session_id, worker_name, started_at)
        VALUES (?, ?, ?)
    """, (session_id, worker_name.strip(), timestamp))

    return session_id


def finish_capture_session_v2(
    conn,
    session_id,
    ended_at,
    reason="STOPPED"
):
    """Close an open capture session."""

    timestamp = _timestamp(ended_at)

    if reason not in {"STOPPED", "ERROR"}:
        raise ValueError("Invalid session end reason")

    cursor = conn.execute("""
        UPDATE capture_sessions_v2
        SET ended_at = ?,
            end_reason = ?
        WHERE session_id = ?
          AND ended_at IS NULL
          AND started_at <= ?
    """, (
        timestamp,
        reason,
        session_id,
        timestamp
    ))

    return cursor.rowcount == 1


def record_session_heartbeat_v2(
    conn,
    session_id,
    recorded_at,
    status
):
    """
    Store one heartbeat per session per minute.

    An ERROR overrides CAPTURING for the same
    session and minute, never the reverse.
    """

    timestamp = _timestamp(recorded_at)

    if status not in {"CAPTURING", "ERROR"}:
        raise ValueError("Invalid heartbeat status")

    minute = recorded_at.replace(
        second=0,
        microsecond=0
    )

    minute_text = _timestamp(minute)

    session = conn.execute("""
        SELECT started_at, ended_at
        FROM capture_sessions_v2
        WHERE session_id = ?
    """, (session_id,)).fetchone()

    if session is None:
        raise ValueError("Unknown capture session")

    started_at, ended_at = session

    if timestamp < started_at:
        raise ValueError("Heartbeat predates session")

    if ended_at is not None and timestamp > ended_at:
        raise ValueError("Heartbeat is after session end")

    conn.execute("""
        INSERT INTO capture_heartbeats_v2
            (session_id, recorded_at, status)
        VALUES (?, ?, ?)
        ON CONFLICT(session_id, recorded_at)
        DO UPDATE SET status = 'ERROR'
        WHERE excluded.status = 'ERROR'
          AND capture_heartbeats_v2.status = 'CAPTURING'
    """, (session_id, minute_text, status))


def assess_session_transitions_v2(
    conn,
    window_end,
    worker_name="packet_capture"
):
    """
    Flag any capture session start or stop inside
    a five-minute observation window.

    This checks transitions only. It does NOT
    independently establish heartbeat coverage
    or healthy packet capture.
    """

    _timestamp(window_end)

    if (
        window_end.minute % 5 != 0
        or window_end.second != 0
        or window_end.microsecond != 0
    ):
        raise ValueError("Window must align to five minutes")

    window_start = window_end - timedelta(minutes=5)

    start_text = _timestamp(window_start)
    end_text = _timestamp(window_end)

    rows = conn.execute("""
        SELECT
            session_id,
            started_at,
            ended_at
        FROM capture_sessions_v2
        WHERE worker_name = ?
          AND (
              (started_at >= ? AND started_at < ?)
              OR
              (ended_at > ? AND ended_at <= ?)
          )
        ORDER BY started_at
    """, (
        worker_name,
        start_text,
        end_text,
        start_text,
        end_text
    )).fetchall()

    transitions = len(rows)

    return {
        "window_start": start_text,
        "window_end": end_text,
        "transition_count": transitions,
        "status": (
            "SESSION_TRANSITION_REVIEW"
            if transitions
            else "NO_SESSION_TRANSITION_DETECTED"
        ),
        "transition_free": transitions == 0
    }
