
import sqlite3
from datetime import datetime, timedelta

from analytics.capture_heartbeat import (
    create_heartbeat_table,
    record_heartbeat,
    assess_heartbeat_window
)

print("=" * 60)
print("STEP 430: CAPTURE HEARTBEAT TEST")
print("=" * 60)

conn = sqlite3.connect(":memory:")

end = datetime(2026, 10, 25, 12, 0)
start = end - timedelta(minutes=5)

passed = 0


def check(name, condition):
    global passed
    assert condition, f"FAIL: {name}"
    passed += 1
    print("PASS:", name)


try:
    create_heartbeat_table(conn)

    empty = assess_heartbeat_window(conn, end)

    check(
        "Missing heartbeat evidence detected",
        empty["status"] == "NO_HEARTBEAT_EVIDENCE"
        and not empty["heartbeat_candidate"]
    )

    # Five healthy heartbeats, spaced 60 seconds apart.
    for minute in range(5):
        inserted = record_heartbeat(
            conn,
            start + timedelta(minutes=minute)
        )
        assert inserted

    healthy = assess_heartbeat_window(conn, end)

    check(
        "Healthy heartbeat coverage accepted",
        healthy["status"] == "HEARTBEAT_COVERAGE_PRESENT"
        and healthy["heartbeat_candidate"]
    )

    check(
        "Heartbeat count correct",
        healthy["heartbeat_count"] == 5
    )

    duplicate = record_heartbeat(conn, start)

    check(
        "Duplicate heartbeat prevented",
        duplicate is False
    )

    # A separate worker with a large heartbeat gap.
    record_heartbeat(
        conn,
        start,
        worker_name="gap_worker"
    )
    record_heartbeat(
        conn,
        start + timedelta(minutes=4),
        worker_name="gap_worker"
    )

    gap = assess_heartbeat_window(
        conn,
        end,
        worker_name="gap_worker"
    )

    check(
        "Large heartbeat gap rejected",
        gap["status"] == "HEARTBEAT_GAP_REVIEW"
        and not gap["heartbeat_candidate"]
    )

    # A worker reporting an explicit error.
    for minute in range(5):
        record_heartbeat(
            conn,
            start + timedelta(minutes=minute),
            worker_name="error_worker",
            status="ERROR" if minute == 2 else "CAPTURING"
        )

    error = assess_heartbeat_window(
        conn,
        end,
        worker_name="error_worker"
    )

    check(
        "Capture worker error rejected",
        error["status"] == "CAPTURE_WORKER_ERROR"
        and error["error_count"] == 1
    )

    try:
        record_heartbeat(
            conn,
            start,
            status="UNKNOWN"
        )
    except ValueError:
        check("Invalid heartbeat status rejected", True)
    else:
        raise AssertionError("Invalid status accepted")

    print("\n" + "=" * 60)
    print("FINAL RESULTS")
    print("=" * 60)
    print("Passed:", passed)
    print("Failed:", 7 - passed)
    print("Overall:", "PASS" if passed == 7 else "FAIL")
    print("Production database changes: NONE")
    print("Capture worker modified: NO")
    print("Automatic baseline learning: DISABLED")
    print("Router operations: NONE")

finally:
    conn.close()
