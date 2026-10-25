
import sqlite3
from datetime import datetime, timedelta
from unittest.mock import patch

import analytics.window_eligibility as eligibility

print("=" * 60)
print("STEP 421: COMBINED WINDOW ELIGIBILITY TEST")
print("=" * 60)

identity = {
    "id": 2,
    "mac_address": "02:11:22:33:44:66",
    "ip_address": "192.168.8.102"
}

window_end = datetime(2026, 10, 24, 10, 45)
current = datetime(2026, 10, 24, 10, 50)

metrics = {
    "device_id": 2,
    "ip_address": "192.168.8.102",
    "window_start": "2026-10-24T10:40:00",
    "window_end": "2026-10-24T10:45:00",
    "packet_count": 250,
    "data_mb": 0.8,
    "dns_requests": 10,
    "distinct_ips": 12,
    "distinct_ports": 5,
}

audit = {
    "status": "ENDPOINTS_CONSISTENT",
    "outbound": 250,
    "inbound": 180,
    "unattributed": 0
}

conn = sqlite3.connect(":memory:")
passed = 0


def run_case(
    name,
    expected_status,
    expected_eligible,
    test_now=None,
    test_identity=None,
    test_metrics=None,
    test_audit=None
):
    global passed

    with (
        patch.object(eligibility, "assess_capture_continuity", return_value={"continuity_candidate": True}),
        patch.object(
            eligibility,
            "get_identity_snapshot",
            return_value=(
                dict(identity)
                if test_identity is None
                else test_identity
            )
        ),
        patch.object(
            eligibility,
            "get_device_window_metrics",
            return_value=(
                dict(metrics)
                if test_metrics is None
                else test_metrics
            )
        ),
        patch.object(
            eligibility,
            "audit_device_traffic",
            return_value=(
                dict(audit)
                if test_audit is None
                else test_audit
            )
        )
    ):
        result = eligibility.assess_window_eligibility(
            conn=conn,
            device_id=2,
            window_end=window_end,
            now=test_now or current
        )

    assert result["status"] == expected_status, result
    assert result["eligible"] == expected_eligible, result

    passed += 1
    print("PASS:", name)


try:
    run_case(
        "Consistent traffic eligible for review",
        "RECENT_QUALIFIED_CANDIDATE",
        True
    )

    run_case(
        "Safety delay enforced",
        "SAFETY_DELAY_NOT_ELAPSED",
        False,
        test_now=window_end + timedelta(minutes=1)
    )

    run_case(
        "Old window rejected",
        "OLD_WINDOW_REVIEW",
        False,
        test_now=window_end + timedelta(minutes=20)
    )

    run_case(
        "Missing device rejected",
        "DEVICE_NOT_FOUND",
        False,
        test_identity={}
    )

    low_traffic = dict(metrics)
    low_traffic["packet_count"] = 5

    low_audit = dict(audit)
    low_audit["outbound"] = 5

    run_case(
        "Insufficient traffic rejected",
        "INSUFFICIENT_TRAFFIC",
        False,
        test_metrics=low_traffic,
        test_audit=low_audit
    )

    bad_audit = dict(audit)
    bad_audit["status"] = "ATTRIBUTION_REVIEW"
    bad_audit["unattributed"] = 12

    run_case(
        "Unattributed traffic rejected",
        "ATTRIBUTION_REVIEW",
        False,
        test_audit=bad_audit
    )

    mismatched_audit = dict(audit)
    mismatched_audit["outbound"] = 200

    run_case(
        "Packet count mismatch rejected",
        "PACKET_COUNT_MISMATCH",
        False,
        test_audit=mismatched_audit
    )

    wrong_ip = dict(metrics)
    wrong_ip["ip_address"] = "192.168.8.110"

    run_case(
        "Measurement IP mismatch rejected",
        "MEASUREMENT_REVIEW",
        False,
        test_metrics=wrong_ip
    )

    print("\n" + "=" * 60)
    print("FINAL RESULTS")
    print("=" * 60)
    print("Passed:", passed)
    print("Failed:", 8 - passed)
    print("Overall:", "PASS" if passed == 8 else "FAIL")
    print("Production database changes: NONE")
    print("Automatic collection: DISABLED")
    print("Baseline learning: DISABLED")

finally:
    conn.close()
