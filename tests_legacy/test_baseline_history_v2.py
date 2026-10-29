
import sqlite3

from analytics.baseline_history_v2 import (
    create_history_table_v2,
    save_observation_v2
)

print("=" * 60)
print("STEP 404: BEHAVIOR HISTORY IDENTITY TEST")
print("=" * 60)

conn = sqlite3.connect(":memory:")
conn.row_factory = sqlite3.Row

passed = 0


def check(name, condition):
    global passed
    assert condition, f"FAIL: {name}"
    passed += 1
    print("PASS:", name)


def rejects(metrics, mac):
    try:
        save_observation_v2(conn, metrics, mac)
        return False
    except ValueError:
        return True


try:
    create_history_table_v2(conn)

    metrics = {
        "device_id": 2,
        "ip_address": "192.168.8.102",
        "window_minutes": 5,
        "window_start": "2026-10-24T10:00:00",
        "window_end": "2026-10-24T10:05:00",
        "packet_count": 250,
        "data_mb": 0.8,
        "dns_requests": 10,
        "distinct_ips": 12,
        "distinct_ports": 5
    }

    mac = "02:11:22:33:44:66"

    check(
        "Valid observation stored",
        save_observation_v2(conn, metrics, mac)
    )

    check(
        "Duplicate prevented",
        save_observation_v2(conn, metrics, mac) is False
    )

    row = conn.execute("""
        SELECT * FROM behaviour_window_history_v2
        WHERE device_id = 2
    """).fetchone()

    check(
        "MAC and IP preserved",
        row["mac_address"] == mac
        and row["observed_ip"] == "192.168.8.102"
    )

    changed_ip = dict(metrics)
    changed_ip["ip_address"] = "192.168.8.110"

    check(
        "Conflicting IP rejected",
        rejects(changed_ip, mac)
    )

    check(
        "Conflicting MAC rejected",
        rejects(metrics, "02:AA:BB:CC:DD:EE")
    )

    check(
        "Placeholder MAC rejected",
        rejects(metrics, "AUTO-CAPTURED")
    )

    unaligned = dict(metrics)
    unaligned["window_start"] = "2026-10-24T10:01:00"
    unaligned["window_end"] = "2026-10-24T10:06:00"

    check(
        "Unaligned window rejected",
        rejects(unaligned, mac)
    )

    future = dict(metrics)
    future["window_start"] = "2099-10-25T10:00:00"
    future["window_end"] = "2099-10-25T10:05:00"

    check(
        "Future window rejected",
        rejects(future, mac)
    )

    invalid = dict(metrics)
    invalid["data_mb"] = -1

    check(
        "Negative bandwidth rejected",
        rejects(invalid, mac)
    )

    print("\n" + "=" * 60)
    print("FINAL RESULTS")
    print("=" * 60)
    print("Passed:", passed)
    print("Failed:", 9 - passed)
    print("Overall:", "PASS" if passed == 9 else "FAIL")

finally:
    conn.close()

print("Production database unchanged.")
