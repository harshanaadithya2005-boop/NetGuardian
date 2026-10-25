
import sqlite3
from datetime import datetime
from unittest.mock import patch

import analytics.scheduled_history as scheduler
import analytics.safe_history_collector as collector

from analytics.baseline_history_v2 import (
    create_history_table_v2
)

print("=" * 60)
print("STEP 413: SCHEDULED HISTORY INTEGRATION")
print("=" * 60)

identities = {
    2: {
        "id": 2,
        "ip_address": "192.168.8.102",
        "mac_address": "02:11:22:33:44:66"
    },
    4: {
        "id": 4,
        "ip_address": "192.168.8.101",
        "mac_address": "02:11:22:33:44:55"
    }
}


def fake_identity(device_id):
    identity = identities.get(device_id)
    return dict(identity) if identity else None


def fake_metrics(device_id, minutes, end_time):
    start = end_time.replace(
        minute=end_time.minute - 5
    )

    identity = identities[device_id]

    return {
        "device_id": device_id,
        "ip_address": identity["ip_address"],
        "window_minutes": 5,
        "window_start": start.isoformat(
            timespec="seconds"
        ),
        "window_end": end_time.isoformat(
            timespec="seconds"
        ),
        "packet_count": 250 if device_id == 2 else 5,
        "data_mb": 0.8 if device_id == 2 else 0.001,
        "dns_requests": 10 if device_id == 2 else 0,
        "distinct_ips": 12 if device_id == 2 else 1,
        "distinct_ports": 5 if device_id == 2 else 1
    }


conn = sqlite3.connect(":memory:")
conn.row_factory = sqlite3.Row

try:
    create_history_table_v2(conn)

    with (
        patch.object(
            collector,
            "get_identity_snapshot",
            side_effect=fake_identity
        ),
        patch.object(
            collector,
            "get_device_window_metrics",
            side_effect=fake_metrics
        )
    ):
        # 10:46 is too early for the 10:40-10:45 window.
        first = scheduler.collect_scheduled_history(
            conn=conn,
            device_ids=[2, 4],
            now=datetime(2026, 10, 24, 10, 46)
        )

        assert first["window_end"] == (
            "2026-10-24T10:40:00"
        )
        assert first["stored"] == 2

        print("PASS: Safety delay selects earlier window")

        # Repeat at the same time.
        duplicate = scheduler.collect_scheduled_history(
            conn=conn,
            device_ids=[2, 4],
            now=datetime(2026, 10, 24, 10, 46)
        )

        assert duplicate["stored"] == 0
        assert duplicate["already_exists"] == 2

        print("PASS: Duplicate collection prevented")

        # At 10:47, the 10:40-10:45 window is eligible.
        next_cycle = scheduler.collect_scheduled_history(
            conn=conn,
            device_ids=[2, 4],
            now=datetime(2026, 10, 24, 10, 47)
        )

        assert next_cycle["window_end"] == (
            "2026-10-24T10:45:00"
        )
        assert next_cycle["stored"] == 2

        print("PASS: Newly eligible window collected")

    conn.commit()

    rows = conn.execute("""
        SELECT *
        FROM behaviour_window_history_v2
        ORDER BY device_id, window_start
    """).fetchall()

    assert len(rows) == 4
    print("PASS: Correct number of observations stored")

    qualified = sum(
        row["quality_status"] == "QUALIFIED"
        for row in rows
    )

    insufficient = sum(
        row["quality_status"] == "INSUFFICIENT"
        for row in rows
    )

    assert qualified == 2
    assert insufficient == 2

    print("PASS: Observation quality classified correctly")

    assert len({
        (row["device_id"], row["window_start"])
        for row in rows
    }) == 4

    print("PASS: Unique device/window identities preserved")

    print("\n" + "=" * 60)
    print("FINAL RESULTS")
    print("=" * 60)
    print("Passed: 6")
    print("Failed: 0")
    print("Overall: PASS")
    print("Production database unchanged.")
    print("No background collector started.")

finally:
    conn.close()
