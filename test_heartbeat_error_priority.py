
"""
NetGuardian - Step 438

Verify ERROR priority in capture heartbeat records.

Uses in-memory SQLite only.
Does not start packet capture or modify production.
"""

import sqlite3
from datetime import datetime

from analytics.capture_heartbeat import (
    create_heartbeat_table
)
from capture.heartbeat_bridge import (
    persist_health_heartbeat
)

print("=" * 60)
print("STEP 438: HEARTBEAT ERROR PRIORITY TEST")
print("=" * 60)

conn = sqlite3.connect(":memory:")

passed = 0


def check(name, condition):
    global passed

    assert condition, f"FAIL: {name}"
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


def saved_status(minute, worker="packet_capture"):
    row = conn.execute("""
        SELECT status
        FROM capture_heartbeats
        WHERE worker_name = ?
          AND recorded_at = ?
    """, (
        worker,
        minute.isoformat(timespec="seconds")
    )).fetchone()

    return row[0] if row else None


try:
    create_heartbeat_table(conn)

    print("\n=== HEALTHY RECORD ===")

    first = persist_health_heartbeat(
        conn,
        healthy,
        datetime(2026, 10, 25, 12, 0, 10)
    )

    minute_1200 = datetime(2026, 10, 25, 12, 0)

    check(
        "Healthy heartbeat initially stored",
        first["inserted"] is True
        and saved_status(minute_1200) == "CAPTURING"
    )

    print("\n=== ERROR IN THE SAME MINUTE ===")

    error = persist_health_heartbeat(
        conn,
        failed,
        datetime(2026, 10, 25, 12, 0, 35)
    )

    check(
        "Failure upgrades healthy heartbeat to ERROR",
        error["updated"] is True
        and saved_status(minute_1200) == "ERROR"
    )

    later_healthy = persist_health_heartbeat(
        conn,
        healthy,
        datetime(2026, 10, 25, 12, 0, 50)
    )

    check(
        "Later healthy heartbeat cannot erase ERROR",
        later_healthy["inserted"] is False
        and later_healthy["updated"] is False
        and saved_status(minute_1200) == "ERROR"
    )

    print("\n=== NEXT MINUTE RECOVERY ===")

    minute_1201 = datetime(2026, 10, 25, 12, 1)

    recovered = persist_health_heartbeat(
        conn,
        healthy,
        datetime(2026, 10, 25, 12, 1, 10)
    )

    check(
        "Healthy heartbeat can be stored next minute",
        recovered["inserted"] is True
        and saved_status(minute_1201) == "CAPTURING"
    )

    check(
        "Earlier error remains preserved",
        saved_status(minute_1200) == "ERROR"
    )

    print("\n=== ERROR FIRST ===")

    minute_1202 = datetime(2026, 10, 25, 12, 2)

    first_error = persist_health_heartbeat(
        conn,
        failed,
        datetime(2026, 10, 25, 12, 2, 5)
    )

    persist_health_heartbeat(
        conn,
        healthy,
        datetime(2026, 10, 25, 12, 2, 45)
    )

    check(
        "ERROR stored first cannot be downgraded",
        first_error["inserted"] is True
        and saved_status(minute_1202) == "ERROR"
    )

    print("\n=== STOPPED WORKER ===")

    ignored = persist_health_heartbeat(
        conn,
        stopped,
        datetime(2026, 10, 25, 12, 3, 15)
    )

    check(
        "Normal stopped worker creates no heartbeat",
        ignored["status"] == "NOT_RECORDED"
        and ignored["inserted"] is False
    )

    print("\n=== WORKER ISOLATION ===")

    another = persist_health_heartbeat(
        conn,
        healthy,
        datetime(2026, 10, 25, 12, 0, 55),
        worker_name="second_worker"
    )

    check(
        "Different workers keep separate records",
        another["inserted"] is True
        and saved_status(
            minute_1200,
            worker="second_worker"
        ) == "CAPTURING"
        and saved_status(minute_1200) == "ERROR"
    )

    print("\n=== FINAL DATABASE CHECK ===")

    conn.commit()

    rows = conn.execute("""
        SELECT worker_name, recorded_at, status
        FROM capture_heartbeats
        ORDER BY worker_name, recorded_at
    """).fetchall()

    for row in rows:
        print(row)

    check(
        "No duplicate worker-minute records",
        len(rows) == len({
            (row[0], row[1]) for row in rows
        })
    )

    check(
        "Expected total heartbeat rows",
        len(rows) == 4
    )

    print("\n" + "=" * 60)
    print("FINAL RESULTS")
    print("=" * 60)

    print("Passed:", passed)
    print("Failed:", 10 - passed)
    print("Overall:", "PASS" if passed == 10 else "FAIL")
    print("Production database changes: NONE")
    print("Real packet capture started: NO")
    print("Automatic heartbeat process: DISABLED")
    print("Baseline learning: DISABLED")
    print("Router operations: NONE")

finally:
    conn.close()
