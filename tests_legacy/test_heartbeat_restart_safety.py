
"""
NetGuardian - Step 441

Heartbeat behavior across capture worker restarts.

Uses temporary SQLite only.

The test intentionally detects a limitation:
a healthy heartbeat from an earlier session can
remain in the same minute after a normal restart.

No real packet capture or production writes.
"""

import sqlite3
import tempfile
from pathlib import Path
from datetime import datetime

from analytics.capture_heartbeat import (
    create_heartbeat_table
)
from capture.heartbeat_reporter import (
    CaptureHeartbeatReporter
)
from capture.worker_health import (
    CaptureWorkerHealth
)

print("=" * 60)
print("STEP 441: HEARTBEAT RESTART SAFETY AUDIT")
print("=" * 60)

passed = 0


def check(name, condition):
    global passed
    assert condition, "FAIL: " + name
    passed += 1
    print("PASS:", name)


with tempfile.TemporaryDirectory() as folder:

    db_path = Path(folder) / "restart_test.db"

    def connect():
        return sqlite3.connect(db_path)

    conn = connect()
    try:
        create_heartbeat_table(conn)
        conn.commit()
    finally:
        conn.close()

    def get_status(minute):
        conn = connect()
        try:
            row = conn.execute("""
                SELECT status
                FROM capture_heartbeats
                WHERE worker_name = 'packet_capture'
                  AND recorded_at = ?
            """, (
                minute.isoformat(timespec="seconds"),
            )).fetchone()

            return row[0] if row else None
        finally:
            conn.close()

    minute_1200 = datetime(2026, 10, 25, 12, 0)
    minute_1201 = datetime(2026, 10, 25, 12, 1)
    minute_1202 = datetime(2026, 10, 25, 12, 2)

    health = CaptureWorkerHealth()
    reporter = CaptureHeartbeatReporter(connect)

    print("\n=== FIRST CAPTURE SESSION ===")

    health.start()
    health.packet_received(now=100)
    health.traffic_persisted(now=101)

    first = reporter.report(
        health.snapshot(now=102),
        datetime(2026, 10, 25, 12, 0, 10)
    )

    check(
        "First healthy session recorded",
        first["written"] is True
        and get_status(minute_1200) == "CAPTURING"
    )

    print("\n=== NORMAL WORKER RESTART ===")

    health.stop()
    health.start()

    restarted = reporter.report(
        health.snapshot(now=110),
        datetime(2026, 10, 25, 12, 0, 30)
    )

    check(
        "New worker cannot claim health without a write",
        restarted["status"] == "NOT_RECORDED"
    )

    old_status = get_status(minute_1200)

    check(
        "Existing same-minute heartbeat still present",
        old_status == "CAPTURING"
    )

    print(
        "REVIEW REQUIRED: Previous session's healthy "
        "heartbeat remains after normal restart."
    )

    health.packet_received(now=115)
    health.traffic_persisted(now=116)

    repeated = reporter.report(
        health.snapshot(now=117),
        datetime(2026, 10, 25, 12, 0, 45)
    )

    check(
        "Same-minute healthy report remains deduplicated",
        repeated["written"] is False
        and get_status(minute_1200) == "CAPTURING"
    )

    print("\n=== NEW MINUTE ===")

    health.traffic_persisted(now=180)

    fresh = reporter.report(
        health.snapshot(now=181),
        datetime(2026, 10, 25, 12, 1, 10)
    )

    check(
        "New minute can record fresh persistence",
        fresh["written"] is True
        and get_status(minute_1201) == "CAPTURING"
    )

    print("\n=== WORKER CRASH ===")

    health.stop(
        error=RuntimeError("Synthetic capture failure")
    )

    crashed = reporter.report(
        health.snapshot(now=190),
        datetime(2026, 10, 25, 12, 1, 35)
    )

    check(
        "Crash upgrades same-minute heartbeat to ERROR",
        crashed["written"] is True
        and get_status(minute_1201) == "ERROR"
    )

    print("\n=== RESTART AFTER CRASH ===")

    health.start()
    health.traffic_persisted(now=200)

    recovery = reporter.report(
        health.snapshot(now=201),
        datetime(2026, 10, 25, 12, 1, 50)
    )

    check(
        "Recovery cannot erase previous crash",
        recovery["written"] is False
        and get_status(minute_1201) == "ERROR"
    )

    health.traffic_persisted(now=260)

    next_minute = reporter.report(
        health.snapshot(now=261),
        datetime(2026, 10, 25, 12, 2, 10)
    )

    check(
        "Subsequent minute records recovery",
        next_minute["written"] is True
        and get_status(minute_1202) == "CAPTURING"
    )

    print("\n=== FINAL SUMMARY ===")

    print("Functional checks passed:", passed)
    print("Functional checks failed:", 8 - passed)
    print(
        "Functional result:",
        "PASS" if passed == 8 else "FAIL"
    )

    print(
        "Normal-restart session ambiguity:",
        "CONFIRMED"
    )

    print("Production database changes: NONE")
    print("Real packet capture started: NO")
    print("Automatic heartbeat reporting: DISABLED")
    print("Baseline learning: DISABLED")
    print("Router operations: NONE")

    assert passed == 8

print("Temporary database deleted.")
print("STEP 441 COMPLETED")
