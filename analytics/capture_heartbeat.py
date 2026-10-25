
"""
NetGuardian - Capture Worker Heartbeat

Provides heartbeat storage and five-minute health
assessment.

The capture worker must eventually call record_heartbeat
after confirming that its capture/write loop is healthy.

This module does NOT start or control packet capture.
"""

from datetime import datetime, timedelta


def create_heartbeat_table(conn):
    """Create heartbeat storage in the supplied database."""

    conn.execute("""
        CREATE TABLE IF NOT EXISTS capture_heartbeats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            recorded_at TEXT NOT NULL,
            worker_name TEXT NOT NULL,
            status TEXT NOT NULL
                CHECK(status IN ('CAPTURING', 'ERROR')),
            UNIQUE(worker_name, recorded_at)
        )
    """)

    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_capture_heartbeat_worker
        ON capture_heartbeats(worker_name, recorded_at)
    """)


def record_heartbeat(
    conn,
    recorded_at,
    worker_name="packet_capture",
    status="CAPTURING"
):
    """Store one heartbeat in the caller's database."""

    if not isinstance(recorded_at, datetime):
        raise TypeError("recorded_at must be datetime")

    if recorded_at.tzinfo is not None:
        raise ValueError("Use local naive timestamps")

    if (
        not isinstance(worker_name, str)
        or not worker_name.strip()
    ):
        raise ValueError("Invalid worker name")

    if status not in {"CAPTURING", "ERROR"}:
        raise ValueError("Invalid heartbeat status")

    cursor = conn.execute("""
        INSERT OR IGNORE INTO capture_heartbeats
            (recorded_at, worker_name, status)
        VALUES (?, ?, ?)
    """, (
        recorded_at.isoformat(timespec="seconds"),
        worker_name.strip(),
        status
    ))

    return cursor.rowcount == 1


def assess_heartbeat_window(
    conn,
    window_end,
    worker_name="packet_capture",
    max_gap_seconds=75
):
    """
    Examine worker heartbeats within a five-minute window.

    Requires:
      - A heartbeat close to the window start
      - A heartbeat close to the window end
      - No excessive gaps between heartbeats
      - No ERROR heartbeat within the window

    This is a heartbeat-coverage check, not proof
    that every packet was captured.
    """

    if not isinstance(window_end, datetime):
        raise TypeError("window_end must be datetime")

    if window_end.tzinfo is not None:
        raise ValueError("Use local naive timestamps")

    if (
        window_end.minute % 5
        or window_end.second
        or window_end.microsecond
    ):
        raise ValueError("Window must end on a five-minute boundary")

    if (
        not isinstance(max_gap_seconds, (int, float))
        or isinstance(max_gap_seconds, bool)
        or not 0 < max_gap_seconds <= 300
    ):
        raise ValueError("Invalid maximum heartbeat gap")

    start = window_end - timedelta(minutes=5)

    rows = conn.execute("""
        SELECT recorded_at, status
        FROM capture_heartbeats
        WHERE worker_name = ?
          AND recorded_at >= ?
          AND recorded_at < ?
        ORDER BY recorded_at
    """, (
        worker_name,
        start.isoformat(timespec="seconds"),
        window_end.isoformat(timespec="seconds")
    )).fetchall()

    timestamps = [
        datetime.fromisoformat(row[0])
        for row in rows
    ]

    errors = sum(row[1] == "ERROR" for row in rows)

    if not timestamps:
        status = "NO_HEARTBEAT_EVIDENCE"

    elif errors:
        status = "CAPTURE_WORKER_ERROR"

    else:
        points = [start] + timestamps + [window_end]

        largest_gap = max(
            (b - a).total_seconds()
            for a, b in zip(points, points[1:])
        )

        status = (
            "HEARTBEAT_COVERAGE_PRESENT"
            if largest_gap <= max_gap_seconds
            else "HEARTBEAT_GAP_REVIEW"
        )

    return {
        "window_start": start.isoformat(timespec="seconds"),
        "window_end": window_end.isoformat(timespec="seconds"),
        "heartbeat_count": len(rows),
        "error_count": errors,
        "status": status,
        "heartbeat_candidate": (
            status == "HEARTBEAT_COVERAGE_PRESENT"
        )
    }
