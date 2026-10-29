
import sqlite3
from datetime import datetime
from unittest.mock import patch

import analytics.safe_history_collector as collector

from analytics.baseline_history_v2 import (
    create_history_table_v2
)

print("=" * 60)
print("STEP 407: SAFE HISTORY COLLECTOR TEST")
print("=" * 60)

identity = {
    "id": 2,
    "ip_address": "192.168.8.102",
    "mac_address": "02:11:22:33:44:66"
}

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

end_time = datetime(2026, 10, 24, 10, 5)

conn = sqlite3.connect(":memory:")
conn.row_factory = sqlite3.Row

passed = 0


def check(name, condition):
    global passed
    assert condition, f"FAIL: {name}"
    passed += 1
    print("PASS:", name)


def count_rows():
    return conn.execute("""
        SELECT COUNT(*)
        FROM behaviour_window_history_v2
    """).fetchone()[0]


try:
    create_history_table_v2(conn)

    print("\n=== TEST 1: VERIFIED COLLECTION ===")

    with (
        patch.object(
            collector,
            "get_identity_snapshot",
            return_value=dict(identity)
        ),
        patch.object(
            collector,
            "get_device_window_metrics",
            return_value=dict(metrics)
        )
    ):
        result = collector.collect_safe_observation(
            conn, 2, end_time
        )

        check(
            "Verified observation stored",
            result["status"] == "STORED"
            and result["stored"] is True
        )

        duplicate = collector.collect_safe_observation(
            conn, 2, end_time
        )

        check(
            "Duplicate observation prevented",
            duplicate["status"] == "ALREADY_EXISTS"
            and count_rows() == 1
        )

    print("\n=== TEST 2: IP CHANGE DURING COLLECTION ===")

    changed_ip = dict(identity)
    changed_ip["ip_address"] = "192.168.8.110"

    with (
        patch.object(
            collector,
            "get_identity_snapshot",
            side_effect=[
                dict(identity),
                changed_ip
            ]
        ),
        patch.object(
            collector,
            "get_device_window_metrics",
            return_value=dict(metrics)
        )
    ):
        result = collector.collect_safe_observation(
            conn, 2, end_time
        )

        check(
            "IP change rejected",
            result["status"] == "IP_CHANGED"
            and not result["stored"]
        )

    print("\n=== TEST 3: MAC CHANGE ===")

    changed_mac = dict(identity)
    changed_mac["mac_address"] = "02:AA:BB:CC:DD:EE"

    with (
        patch.object(
            collector,
            "get_identity_snapshot",
            side_effect=[
                dict(identity),
                changed_mac
            ]
        ),
        patch.object(
            collector,
            "get_device_window_metrics",
            return_value=dict(metrics)
        )
    ):
        result = collector.collect_safe_observation(
            conn, 2, end_time
        )

        check(
            "MAC change rejected",
            result["status"] == "MAC_CHANGED"
            and not result["stored"]
        )

    print("\n=== TEST 4: MEASUREMENT IP MISMATCH ===")

    mismatched = dict(metrics)
    mismatched["ip_address"] = "192.168.8.110"

    with (
        patch.object(
            collector,
            "get_identity_snapshot",
            return_value=dict(identity)
        ),
        patch.object(
            collector,
            "get_device_window_metrics",
            return_value=mismatched
        )
    ):
        result = collector.collect_safe_observation(
            conn, 2, end_time
        )

        check(
            "Measurement IP mismatch rejected",
            result["status"] == "MEASUREMENT_IP_MISMATCH"
            and not result["stored"]
        )

    print("\n=== TEST 5: MISSING DEVICE ===")

    with patch.object(
        collector,
        "get_identity_snapshot",
        return_value=None
    ):
        result = collector.collect_safe_observation(
            conn, 999999, end_time
        )

        check(
            "Missing device safely skipped",
            result["status"] == "DEVICE_NOT_FOUND"
            and not result["stored"]
        )

    print("\n=== TEST 6: DATABASE SAFETY ===")

    check(
        "Rejected observations created no extra rows",
        count_rows() == 1
    )

    print("\n" + "=" * 60)
    print("FINAL RESULTS")
    print("=" * 60)
    print("Passed:", passed)
    print("Failed:", 7 - passed)
    print("Overall:", "PASS" if passed == 7 else "FAIL")

finally:
    conn.close()

print("Production database unchanged.")
print("Router operations: None")
