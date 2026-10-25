
"""
NetGuardian - Step 428

Verify that behavioral eligibility respects
capture-continuity evidence.

Uses mocks and temporary SQLite only.
No production database writes.
"""

import sqlite3
from datetime import datetime
from unittest.mock import patch

import analytics.window_eligibility as eligibility

print("=" * 60)
print("STEP 428: CAPTURE CONTINUITY ELIGIBILITY TEST")
print("=" * 60)

identity = {
    "id": 2,
    "mac_address": "02:11:22:33:44:66",
    "ip_address": "192.168.8.102"
}

metrics = {
    "device_id": 2,
    "ip_address": "192.168.8.102",
    "window_start": "2026-10-24T10:40:00",
    "window_end": "2026-10-24T10:45:00",
    "packet_count": 250,
    "data_mb": 0.8,
    "dns_requests": 10,
    "distinct_ips": 12,
    "distinct_ports": 5
}

audit = {
    "status": "ENDPOINTS_CONSISTENT",
    "total": 430,
    "outbound": 250,
    "inbound": 180,
    "unattributed": 0
}

WINDOW_END = datetime(2026, 10, 24, 10, 45)
NOW = datetime(2026, 10, 24, 10, 50)

conn = sqlite3.connect(":memory:")
passed = 0


def check(name, condition):
    global passed
    assert condition, "FAIL: " + name
    passed += 1
    print("PASS:", name)


def assess_with_counts(minute_counts):
    active = sum(count > 0 for count in minute_counts)

    continuity = {
        "minute_counts": minute_counts,
        "active_minutes": active,
        "total_packets": sum(minute_counts),
        "continuity_candidate": active == 5,
        "status": (
            "CAPTURE_EVIDENCE_PRESENT"
            if active == 5
            else (
                "NO_CAPTURE_EVIDENCE"
                if active == 0
                else "PARTIAL_CAPTURE_EVIDENCE"
            )
        )
    }

    with (
        patch.object(
            eligibility,
            "get_identity_snapshot",
            return_value=dict(identity)
        ),
        patch.object(
            eligibility,
            "get_device_window_metrics",
            return_value=dict(metrics)
        ),
        patch.object(
            eligibility,
            "audit_device_traffic",
            return_value=dict(audit)
        ),
        patch.object(
            eligibility,
            "assess_capture_continuity",
            return_value=continuity
        ) as continuity_mock
    ):
        result = eligibility.assess_window_eligibility(
            conn=conn,
            device_id=2,
            window_end=WINDOW_END,
            now=NOW
        )

        assert continuity_mock.call_count == 1
        return result


try:
    print("\n=== COMPLETE CAPTURE EVIDENCE ===")

    result = assess_with_counts(
        [50, 60, 40, 55, 45]
    )

    check(
        "Complete capture evidence accepted",
        result["status"] == "RECENT_QUALIFIED_CANDIDATE"
        and result["eligible"] is True
    )

    print("\n=== PARTIAL CAPTURE EVIDENCE ===")

    result = assess_with_counts(
        [50, 60, 0, 55, 45]
    )

    check(
        "Missing middle minute rejected",
        result["status"] == "CAPTURE_CONTINUITY_REVIEW"
        and result["eligible"] is False
    )

    result = assess_with_counts(
        [0, 60, 40, 55, 45]
    )

    check(
        "Missing first minute rejected",
        result["status"] == "CAPTURE_CONTINUITY_REVIEW"
        and result["eligible"] is False
    )

    result = assess_with_counts(
        [50, 60, 40, 55, 0]
    )

    check(
        "Missing last minute rejected",
        result["status"] == "CAPTURE_CONTINUITY_REVIEW"
        and result["eligible"] is False
    )

    print("\n=== EMPTY CAPTURE WINDOW ===")

    # Artificially keep the device packet-count mock at
    # 250 to prove the continuity gate independently blocks
    # inconsistent or incomplete capture evidence.
    result = assess_with_counts(
        [0, 0, 0, 0, 0]
    )

    check(
        "No global capture evidence rejected",
        result["status"] == "CAPTURE_CONTINUITY_REVIEW"
        and result["eligible"] is False
    )

    print("\n=== DATA SAFETY ===")

    table_count = conn.execute("""
        SELECT COUNT(*)
        FROM sqlite_master
        WHERE type = 'table'
          AND name NOT LIKE 'sqlite_%'
    """).fetchone()[0]

    check(
        "Test created no history tables",
        table_count == 0
    )

    print("\n" + "=" * 60)
    print("FINAL RESULTS")
    print("=" * 60)
    print("Passed:", passed)
    print("Failed:", 6 - passed)
    print("Overall:", "PASS" if passed == 6 else "FAIL")
    print("Production database changes: NONE")
    print("Automatic collection: DISABLED")
    print("Baseline learning: DISABLED")
    print("Router operations: NONE")

finally:
    conn.close()
