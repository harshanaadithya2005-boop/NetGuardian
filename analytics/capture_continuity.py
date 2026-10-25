
"""
NetGuardian - Capture Continuity Assessment

Read-only analysis of global packet recording coverage
within completed five-minute windows.

This is an evidence-based heuristic, not proof
that capture ran continuously.
"""

from datetime import datetime, timedelta


def assess_capture_continuity(conn, window_end):
    if not isinstance(window_end, datetime):
        raise TypeError("window_end must be datetime")

    if window_end.tzinfo is not None:
        raise ValueError("Use local naive timestamps")

    if (
        window_end.minute % 5 != 0
        or window_end.second != 0
        or window_end.microsecond != 0
    ):
        raise ValueError("Window end must align to five minutes")

    window_start = window_end - timedelta(minutes=5)
    minute_counts = []

    for i in range(5):
        start = window_start + timedelta(minutes=i)
        end = start + timedelta(minutes=1)

        count = conn.execute("""
            SELECT COUNT(*)
            FROM traffic
            WHERE datetime(timestamp) >= datetime(?)
              AND datetime(timestamp) < datetime(?)
              AND COALESCE(is_simulated, 0) = 0
        """, (
            start.isoformat(timespec="seconds"),
            end.isoformat(timespec="seconds")
        )).fetchone()[0]

        minute_counts.append(count)

    active_minutes = sum(
        count > 0 for count in minute_counts
    )

    total_packets = sum(minute_counts)

    if active_minutes == 5:
        status = "CAPTURE_EVIDENCE_PRESENT"
    elif active_minutes == 0:
        status = "NO_CAPTURE_EVIDENCE"
    else:
        status = "PARTIAL_CAPTURE_EVIDENCE"

    return {
        "window_start": window_start.isoformat(
            timespec="seconds"
        ),
        "window_end": window_end.isoformat(
            timespec="seconds"
        ),
        "minute_counts": minute_counts,
        "active_minutes": active_minutes,
        "total_packets": total_packets,
        "status": status,
        "continuity_candidate": active_minutes == 5
    }
