
"""
NetGuardian - Step 440

Rate-limited heartbeat reporter integration tests.

Uses a temporary SQLite file outside production.
No Scapy capture, monitoring, or router operations.
"""

import sqlite3
import tempfile
from pathlib import Path
from datetime import datetime

from analytics.capture_heartbeat import create_heartbeat_table
from capture.heartbeat_reporter import CaptureHeartbeatReporter


print("=" * 60)
print("STEP 440: SAFE HEARTBEAT REPORTER TEST")
print("=" * 60)

passed = 0


def check(name, condition):
    global passed
    assert condition, "FAIL: " + name
    passed += 1
    print("PASS:", name)


healthy = {
    "status": "CAPTURING",
    "running": True,
    "recent_successful_write": True,
    "heartbeat_candidate": True,
    "worker_error": None
}

failed = {
    "status": "WRITE_ERROR",
    "running": True,
    "recent_successful_write": False,
    "heartbeat_candidate": False,
    "worker_error": None
}

stopped = {
    "status": "STOPPED",
    "running": False,
    "recent_successful_write": False,
    "heartbeat_candidate": False,
    "worker_error": None
}


with tempfile.TemporaryDirectory() as folder:
    db_path = Path(folder) / "heartbeat_test.db"

    def connection_factory():
        return sqlite3.connect(db_path)

    conn = connection_factory()
    create_heartbeat_table(conn)
    conn.commit()
    conn.close()

    reporter = CaptureHeartbeatReporter(connection_factory)

    def get_status(minute):
        conn = connection_factory()
        try:
            row = conn.execute("""
                SELECT status
                FROM capture_heartbeats
                WHERE worker_name = 'packet_capture'
                  AND recorded_at = ?
            """, (minute,)).fetchone()

            return row[0] if row else None
        finally:
            conn.close()

    def count_rows():
        conn = connection_factory()
        try:
            return conn.execute("""
                SELECT COUNT(*)
                FROM capture_heartbeats
            """).fetchone()[0]
        finally:
            conn.close()

    print("\n=== HEALTHY REPORTING ===")

    first = reporter.report(
        healthy,
        datetime(2026, 10, 25, 12, 0, 10)
    )

    check(
        "Healthy heartbeat stored",
        first["written"] is True
        and get_status("2026-10-25T12:00:00") == "CAPTURING"
    )

    second = reporter.report(
        healthy,
        datetime(2026, 10, 25, 12, 0, 20)
    )

    check(
        "Repeated healthy report rate-limited",
        second["status"] == "ALREADY_REPORTED"
        and count_rows() == 1
    )

    print("\n=== SAME-MINUTE ERROR PRIORITY ===")

    error = reporter.report(
        failed,
        datetime(2026, 10, 25, 12, 0, 35)
    )

    check(
        "Error upgrades earlier healthy record",
        error["written"] is True
        and get_status("2026-10-25T12:00:00") == "ERROR"
    )

    later = reporter.report(
        healthy,
        datetime(2026, 10, 25, 12, 0, 50)
    )

    check(
        "Healthy report cannot erase error",
        later["written"] is False
        and get_status("2026-10-25T12:00:00") == "ERROR"
    )

    print("\n=== NEXT MINUTE ===")

    recovered = reporter.report(
        healthy,
        datetime(2026, 10, 25, 12, 1, 10)
    )

    check(
        "Next-minute recovery recorded",
        recovered["written"] is True
        and get_status("2026-10-25T12:01:00") == "CAPTURING"
    )

    print("\n=== STOPPED WORKER ===")

    ignored = reporter.report(
        stopped,
        datetime(2026, 10, 25, 12, 2, 10)
    )

    check(
        "Stopped worker does not claim healthy",
        ignored["status"] == "NOT_RECORDED"
        and count_rows() == 2
    )

    print("\n=== DATABASE ERROR ISOLATION ===")

    attempts = [0]

    def failing_factory():
        attempts[0] += 1
        raise sqlite3.OperationalError(
            "Synthetic database unavailable"
        )

    failing = CaptureHeartbeatReporter(failing_factory)

    result = failing.report(
        healthy,
        datetime(2026, 10, 25, 12, 3, 10)
    )

    check(
        "Database failure safely contained",
        result["status"] == "HEARTBEAT_WRITE_FAILED"
        and result["written"] is False
    )

    check(
        "Database connection failure attempted",
        attempts[0] == 1
    )

    print("\n=== RETRY AFTER FAILURE ===")

    failing.connection_factory = connection_factory

    retry = failing.report(
        healthy,
        datetime(2026, 10, 25, 12, 3, 20)
    )

    check(
        "Same-minute retry succeeds",
        retry["written"] is True
        and get_status("2026-10-25T12:03:00") == "CAPTURING"
    )

    print("\n=== FINAL DATABASE VERIFICATION ===")

    check(
        "Expected heartbeat count",
        count_rows() == 3
    )

    print("\n" + "=" * 60)
    print("FINAL RESULTS")
    print("=" * 60)
    print("Passed:", passed)
    print("Failed:", 10 - passed)
    print("Overall:", "PASS" if passed == 10 else "FAIL")
    print("Production database changes: NONE")
    print("Real packet capture started: NO")
    print("Automatic heartbeat reporting: DISABLED")
    print("Baseline learning: DISABLED")
    print("Router operations: NONE")

print("Temporary test database deleted.")
