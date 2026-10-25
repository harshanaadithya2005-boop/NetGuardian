
"""
NetGuardian - Step 442

Test session-aware capture history across restarts.

All database operations use isolated in-memory SQLite.
"""

import sqlite3
from datetime import datetime

from analytics.capture_sessions_v2 import (
    create_session_tables_v2,
    start_capture_session_v2,
    finish_capture_session_v2,
    record_session_heartbeat_v2,
    assess_session_transitions_v2
)

print("=" * 60)
print("STEP 442: SESSION-AWARE HEARTBEAT TEST")
print("=" * 60)

conn = sqlite3.connect(":memory:")
conn.execute("PRAGMA foreign_keys = ON")

passed = 0


def check(name, condition):
    global passed
    assert condition, "FAIL: " + name
    passed += 1
    print("PASS:", name)


def heartbeat_status(session_id, minute):
    row = conn.execute("""
        SELECT status
        FROM capture_heartbeats_v2
        WHERE session_id = ?
          AND recorded_at = ?
    """, (session_id, minute)).fetchone()

    return row[0] if row else None


try:
    create_session_tables_v2(conn)

    print("\n=== FIRST CAPTURE SESSION ===")

    first_session = start_capture_session_v2(
        conn,
        datetime(2026, 10, 25, 11, 59, 50)
    )

    check(
        "First session created",
        isinstance(first_session, str)
        and len(first_session) == 32
    )

    print("\n=== OVERLAPPING SESSION PROTECTION ===")

    try:
        start_capture_session_v2(
            conn,
            datetime(2026, 10, 25, 12, 0, 5)
        )
    except sqlite3.IntegrityError:
        check("Second active session rejected", True)
    else:
        raise AssertionError("Overlapping session accepted")

    record_session_heartbeat_v2(
        conn,
        first_session,
        datetime(2026, 10, 25, 12, 0, 10),
        "CAPTURING"
    )

    check(
        "First session heartbeat stored",
        heartbeat_status(
            first_session,
            "2026-10-25T12:00:00"
        ) == "CAPTURING"
    )

    print("\n=== FIRST SESSION SHUTDOWN ===")

    closed = finish_capture_session_v2(
        conn,
        first_session,
        datetime(2026, 10, 25, 12, 0, 20)
    )

    check(
        "First session closed",
        closed is True
    )

    print("\n=== SECOND CAPTURE SESSION ===")

    second_session = start_capture_session_v2(
        conn,
        datetime(2026, 10, 25, 12, 0, 30)
    )

    check(
        "Restart creates a different session ID",
        second_session != first_session
    )

    record_session_heartbeat_v2(
        conn,
        second_session,
        datetime(2026, 10, 25, 12, 0, 45),
        "CAPTURING"
    )

    check(
        "Same-minute heartbeats remain session-specific",
        heartbeat_status(
            first_session,
            "2026-10-25T12:00:00"
        ) == "CAPTURING"
        and heartbeat_status(
            second_session,
            "2026-10-25T12:00:00"
        ) == "CAPTURING"
    )

    print("\n=== RESTART WINDOW REVIEW ===")

    transition = assess_session_transitions_v2(
        conn,
        datetime(2026, 10, 25, 12, 5)
    )

    print("Transition status:", transition["status"])
    print("Sessions with transitions:",
          transition["transition_count"])

    check(
        "Restart window flagged for review",
        transition["status"] == "SESSION_TRANSITION_REVIEW"
        and not transition["transition_free"]
        and transition["transition_count"] == 2
    )

    print("\n=== ERROR PRIORITY WITHIN SESSION ===")

    record_session_heartbeat_v2(
        conn,
        second_session,
        datetime(2026, 10, 25, 12, 0, 50),
        "ERROR"
    )

    record_session_heartbeat_v2(
        conn,
        second_session,
        datetime(2026, 10, 25, 12, 0, 55),
        "CAPTURING"
    )

    check(
        "ERROR preserved for second session",
        heartbeat_status(
            second_session,
            "2026-10-25T12:00:00"
        ) == "ERROR"
        and heartbeat_status(
            first_session,
            "2026-10-25T12:00:00"
        ) == "CAPTURING"
    )

    print("\n=== POST-RESTART WINDOW ===")

    clean_window = assess_session_transitions_v2(
        conn,
        datetime(2026, 10, 25, 12, 10)
    )

    check(
        "Window without restarts has no transitions",
        clean_window["status"]
        == "NO_SESSION_TRANSITION_DETECTED"
        and clean_window["transition_free"]
    )

    print("\n=== FINAL DATABASE CHECK ===")

    sessions = conn.execute("""
        SELECT COUNT(*)
        FROM capture_sessions_v2
    """).fetchone()[0]

    heartbeats = conn.execute("""
        SELECT COUNT(*)
        FROM capture_heartbeats_v2
    """).fetchone()[0]

    check(
        "Two sessions and two distinct heartbeat rows",
        sessions == 2 and heartbeats == 2
    )

    print("\n" + "=" * 60)
    print("FINAL RESULTS")
    print("=" * 60)
    print("Passed:", passed)
    print("Failed:", 10 - passed)
    print("Overall:", "PASS" if passed == 10 else "FAIL")
    print("Production database changes: NONE")
    print("Existing heartbeat schema modified: NO")
    print("Real packet capture started: NO")
    print("Automatic heartbeat reporting: DISABLED")
    print("Baseline learning: DISABLED")
    print("Router operations: NONE")

finally:
    conn.close()
