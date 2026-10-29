
import sqlite3
from analytics.baseline_history import (
    create_history_table,
    save_observation
)

print("=" * 60)
print("STEP 399: HISTORICAL BASELINE STORAGE TEST")
print("=" * 60)

conn = sqlite3.connect(":memory:")
conn.row_factory = sqlite3.Row

try:
    create_history_table(conn)

    example = {
        "device_id": 2,
        "window_minutes": 5,
        "window_start": "2026-10-24T10:00:00",
        "window_end": "2026-10-24T10:05:00",
        "packet_count": 250,
        "data_mb": 0.8,
        "dns_requests": 10,
        "distinct_ips": 12,
        "distinct_ports": 5
    }

    checks = {}

    checks["First observation inserted"] = (
        save_observation(conn, example) is True
    )

    checks["Duplicate observation prevented"] = (
        save_observation(conn, example) is False
    )

    row = conn.execute("""
        SELECT * FROM behaviour_window_history
        WHERE device_id = 2
    """).fetchone()

    checks["Stored bandwidth correct"] = (
        row["data_mb"] == 0.8
    )

    checks["Quality classified correctly"] = (
        row["quality_status"] == "QUALIFIED"
    )

    low_traffic = dict(example)
    low_traffic["device_id"] = 4
    low_traffic["packet_count"] = 5

    save_observation(conn, low_traffic)

    row = conn.execute("""
        SELECT quality_status
        FROM behaviour_window_history
        WHERE device_id = 4
    """).fetchone()

    checks["Sparse observations marked insufficient"] = (
        row["quality_status"] == "INSUFFICIENT"
    )

    try:
        bad = dict(example)
        bad["device_id"] = 30
        bad["data_mb"] = -1
        save_observation(conn, bad)
        checks["Negative bandwidth rejected"] = False
    except ValueError:
        checks["Negative bandwidth rejected"] = True

    try:
        bad = dict(example)
        bad["device_id"] = 31
        bad["window_minutes"] = 30
        save_observation(conn, bad)
        checks["Wrong window duration rejected"] = False
    except ValueError:
        checks["Wrong window duration rejected"] = True

    print("\n=== TEST RESULTS ===")

    for name, success in checks.items():
        print(f"{'PASS' if success else 'FAIL'} | {name}")

    passed = sum(checks.values())
    failed = len(checks) - passed

    print("\n" + "=" * 60)
    print("FINAL RESULTS")
    print("=" * 60)
    print("Passed:", passed)
    print("Failed:", failed)
    print("Overall:", "PASS" if failed == 0 else "FAIL")

    assert failed == 0

finally:
    conn.close()

print("In-memory database closed.")
print("Production database unchanged.")
