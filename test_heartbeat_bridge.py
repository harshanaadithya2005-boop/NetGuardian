
"""
NetGuardian - Step 437

Tests capture-worker health to heartbeat integration.

Uses in-memory SQLite only.
Does not start Scapy or update production.
"""

import sqlite3
from datetime import datetime

from analytics.capture_heartbeat import (
    create_heartbeat_table
)
from capture.heartbeat_bridge import (
    heartbeat_status_for_snapshot,
    persist_health_heartbeat
)
from capture.worker_health import CaptureWorkerHealth


print("=" * 60)
print("STEP 437: WORKER HEALTH HEARTBEAT BRIDGE")
print("=" * 60)

passed = 0


def check(name, condition):
    global passed
    assert condition, "FAIL: " + name
    passed += 1
    print("PASS:", name)


conn = sqlite3.connect(":memory:")

try:
    create_heartbeat_table(conn)

    health = CaptureWorkerHealth(
        max_write_age_seconds=75
    )

    when = datetime(2026, 10, 25, 12, 0, 15)

    print("\n=== STOPPED AND UNVERIFIED STATES ===")

    stopped = persist_health_heartbeat(
        conn, health.snapshot(now=100), when
    )

    check(
        "Stopped worker does not report healthy",
        stopped["status"] == "NOT_RECORDED"
        and stopped["inserted"] is False
    )

    health.start()
    health.packet_received(now=110)

    unverified = persist_health_heartbeat(
        conn, health.snapshot(now=110), when
    )

    check(
        "Packet reception without persistence is rejected",
        unverified["status"] == "NOT_RECORDED"
    )

    print("\n=== SUCCESSFUL PERSISTENCE ===")

    health.traffic_persisted(now=115)

    healthy_snapshot = health.snapshot(now=120)

    healthy = persist_health_heartbeat(
        conn, healthy_snapshot, when
    )

    check(
        "Verified healthy candidate creates heartbeat",
        healthy["status"] == "CAPTURING"
        and healthy["inserted"] is True
    )

    duplicate = persist_health_heartbeat(
        conn,
        healthy_snapshot,
        datetime(2026, 10, 25, 12, 0, 40)
    )

    check(
        "Repeated heartbeat in same minute prevented",
        duplicate["inserted"] is False
    )

    print("\n=== WRITE FAILURE ===")

    health.persistence_failed(
        error=RuntimeError("Synthetic write failure"),
        now=125
    )

    failed_snapshot = health.snapshot(now=126)

    failure = persist_health_heartbeat(
        conn,
        failed_snapshot,
        datetime(2026, 10, 25, 12, 1, 10)
    )

    check(
        "Database persistence failure records ERROR",
        failure["status"] == "ERROR"
        and failure["inserted"] is True
    )

    print("\n=== WORKER EXCEPTION ===")

    health.stop(
        error=RuntimeError("Synthetic sniff failure")
    )

    crashed = persist_health_heartbeat(
        conn,
        health.snapshot(now=130),
        datetime(2026, 10, 25, 12, 2, 10)
    )

    check(
        "Stopped worker with exception records ERROR",
        crashed["status"] == "ERROR"
        and crashed["inserted"] is True
    )

    print("\n=== HEARTBEAT TABLE VERIFICATION ===")

    rows = conn.execute("""
        SELECT recorded_at, status
        FROM capture_heartbeats
        ORDER BY recorded_at
    """).fetchall()

    check(
        "Expected heartbeat sequence stored",
        [row[1] for row in rows]
        == ["CAPTURING", "ERROR", "ERROR"]
    )

    print("\n=== RESTART SAFETY ===")

    health.start()

    restarted = heartbeat_status_for_snapshot(
        health.snapshot(now=200)
    )

    check(
        "Restart cannot reuse old healthy state",
        restarted is None
    )

    print("\n" + "=" * 60)
    print("FINAL RESULTS")
    print("=" * 60)
    print("Passed:", passed)
    print("Failed:", 8 - passed)
    print("Overall:", "PASS" if passed == 8 else "FAIL")
    print("Production database changes: NONE")
    print("Real packet capture started: NO")
    print("Automatic heartbeat process: DISABLED")
    print("Baseline learning: DISABLED")
    print("Router operations: NONE")

finally:
    conn.close()
