
"""
NetGuardian - Step 439

Complete worker health -> heartbeat -> window assessment.

Uses synthetic worker events and in-memory SQLite only.

No real packet capture, production writes,
baseline changes or router operations.
"""

import sqlite3
from datetime import datetime, timedelta

from capture.worker_health import CaptureWorkerHealth

from capture.heartbeat_bridge import persist_health_heartbeat

from analytics.capture_heartbeat import (
    create_heartbeat_table,
    assess_heartbeat_window
)


print("=" * 60)
print("STEP 439: COMPLETE HEARTBEAT PIPELINE TEST")
print("=" * 60)

conn = sqlite3.connect(":memory:")
conn.row_factory = sqlite3.Row

health = CaptureWorkerHealth(
    max_write_age_seconds=75
)

passed = 0


def check(name, condition):
    global passed

    assert condition, "FAIL: " + name

    passed += 1
    print("PASS:", name)


def stored_status(worker_name, minute):
    row = conn.execute("""
        SELECT status
        FROM capture_heartbeats
        WHERE worker_name = ?
          AND recorded_at = ?
    """, (
        worker_name,
        minute.isoformat(timespec="seconds")
    )).fetchone()

    return row["status"] if row else None


def submit(snapshot, timestamp, worker="packet_capture"):
    return persist_health_heartbeat(
        conn=conn,
        snapshot=snapshot,
        recorded_at=timestamp,
        worker_name=worker
    )


try:
    create_heartbeat_table(conn)

    start = datetime(2026, 10, 25, 12, 0)

    print("\n=== WORKER STARTUP ===")

    stopped = submit(
        health.snapshot(now=100),
        start
    )

    check(
        "Stopped worker cannot generate healthy heartbeat",
        stopped["status"] == "NOT_RECORDED"
    )

    health.start(now=100)

    starting = submit(
        health.snapshot(now=101),
        start + timedelta(seconds=5)
    )

    check(
        "Worker startup alone does not prove health",
        starting["status"] == "NOT_RECORDED"
    )

    health.packet_received(now=105)

    received = submit(
        health.snapshot(now=106),
        start + timedelta(seconds=10)
    )

    check(
        "Packet reception alone cannot generate heartbeat",
        received["status"] == "NOT_RECORDED"
    )

    print("\n=== SUCCESSFUL DATABASE WRITE ===")

    health.traffic_persisted(now=110)

    healthy = submit(
        health.snapshot(now=111),
        start + timedelta(seconds=15)
    )

    check(
        "Successful persistence generates healthy heartbeat",
        healthy["inserted"] is True
        and stored_status(
            "packet_capture", start
        ) == "CAPTURING"
    )

    repeated = submit(
        health.snapshot(now=115),
        start + timedelta(seconds=20)
    )

    check(
        "Repeated healthy status does not duplicate record",
        repeated["inserted"] is False
    )

    print("\n=== FAILURE AND RECOVERY ===")

    health.persistence_failed(
        error=RuntimeError("Synthetic SQLite failure"),
        now=120
    )

    failed = submit(
        health.snapshot(now=121),
        start + timedelta(seconds=30)
    )

    check(
        "Write failure upgrades same-minute status",
        failed["updated"] is True
        and stored_status(
            "packet_capture", start
        ) == "ERROR"
    )

    health.traffic_persisted(now=130)

    submit(
        health.snapshot(now=131),
        start + timedelta(seconds=40)
    )

    check(
        "Recovery cannot erase earlier same-minute error",
        stored_status(
            "packet_capture", start
        ) == "ERROR"
    )

    print("\n=== NEXT-MINUTE RECOVERY ===")

    next_minute = start + timedelta(minutes=1)

    health.traffic_persisted(now=180)

    recovered = submit(
        health.snapshot(now=181),
        next_minute + timedelta(seconds=10)
    )

    check(
        "Healthy next-minute recovery recorded",
        recovered["inserted"] is True
        and stored_status(
            "packet_capture", next_minute
        ) == "CAPTURING"
    )

    print("\n=== STALE WORKER ACTIVITY ===")

    stale = submit(
        health.snapshot(now=300),
        start + timedelta(minutes=2)
    )

    check(
        "Stale successful write cannot claim healthy capture",
        stale["status"] == "NOT_RECORDED"
    )

    print("\n=== SNIFFER FAILURE ===")

    health.stop(
        error=RuntimeError("Synthetic sniff failure")
    )

    error_time = start + timedelta(minutes=2)

    crashed = submit(
        health.snapshot(now=310),
        error_time + timedelta(seconds=15)
    )

    check(
        "Sniffer exception generates ERROR heartbeat",
        crashed["status"] == "ERROR"
        and crashed["inserted"] is True
    )

    print("\n=== ERROR WINDOW ASSESSMENT ===")

    error_assessment = assess_heartbeat_window(
        conn=conn,
        window_end=start + timedelta(minutes=5)
    )

    check(
        "Window containing worker error rejected",
        error_assessment["status"]
        == "CAPTURE_WORKER_ERROR"
        and not error_assessment["heartbeat_candidate"]
    )

    print("\n=== INDEPENDENT HEALTHY WORKER ===")

    clean_health = CaptureWorkerHealth(
        max_write_age_seconds=75
    )

    clean_health.start()

    for minute in range(5):
        simulated_time = 500 + minute * 60

        clean_health.packet_received(
            now=simulated_time
        )

        clean_health.traffic_persisted(
            now=simulated_time
        )

        result = submit(
            clean_health.snapshot(
                now=simulated_time + 1
            ),
            start + timedelta(minutes=minute),
            worker="clean_worker"
        )

        assert result["inserted"] is True

    clean_assessment = assess_heartbeat_window(
        conn=conn,
        window_end=start + timedelta(minutes=5),
        worker_name="clean_worker"
    )

    check(
        "Five-minute healthy worker coverage accepted",
        clean_assessment["status"]
        == "HEARTBEAT_COVERAGE_PRESENT"
        and clean_assessment["heartbeat_candidate"]
    )

    print("\n=== DATABASE INTEGRITY ===")

    conn.commit()

    rows = conn.execute("""
        SELECT worker_name, recorded_at, status
        FROM capture_heartbeats
        ORDER BY worker_name, recorded_at
    """).fetchall()

    for row in rows:
        print(dict(row))

    check(
        "Expected number of heartbeat records",
        len(rows) == 8
    )

    print("\n" + "=" * 60)
    print("FINAL RESULTS")
    print("=" * 60)
    print("Passed:", passed)
    print("Failed:", 13 - passed)
    print(
        "Overall:",
        "PASS" if passed == 13 else "FAIL"
    )
    print("Production database changes: NONE")
    print("Real packet capture started: NO")
    print("Automatic heartbeat process: DISABLED")
    print("Baseline learning: DISABLED")
    print("Router operations: NONE")

finally:
    conn.close()
