
"""
NetGuardian - Step 423

Test that eligibility is required before collecting
behavioral history observations.

Uses mock functions and in-memory SQLite only.
"""

import sqlite3
from datetime import datetime
from unittest.mock import patch

import analytics.eligibility_collector as gate

print("=" * 60)
print("STEP 423: ELIGIBILITY-GATED COLLECTION TEST")
print("=" * 60)

WINDOW_END = datetime(2026, 10, 24, 10, 45)
NOW = datetime(2026, 10, 24, 10, 50)

history_conn = sqlite3.connect(":memory:")
audit_conn = sqlite3.connect(":memory:")

passed = 0


def check(name, condition):
    global passed

    assert condition, "FAIL: " + name
    passed += 1
    print("PASS:", name)


def test_gate(
    eligibility_status,
    eligibility_allowed,
    expected_collector_calls,
    collector_status="STORED"
):
    with (
        patch.object(
            gate,
            "assess_window_eligibility",
            return_value={
                "device_id": 2,
                "status": eligibility_status,
                "eligible": eligibility_allowed
            }
        ) as assess_mock,
        patch.object(
            gate,
            "collect_safe_observation",
            return_value={
                "device_id": 2,
                "status": collector_status,
                "stored": collector_status == "STORED"
            }
        ) as collect_mock
    ):
        result = gate.collect_eligible_observation(
            history_conn=history_conn,
            audit_conn=audit_conn,
            device_id=2,
            window_end=WINDOW_END,
            now=NOW
        )

        assert assess_mock.call_count == 1
        assert collect_mock.call_count == (
            expected_collector_calls
        )

        return result, collect_mock


try:
    print("\n=== ELIGIBLE WINDOW ===")

    result, collector = test_gate(
        "RECENT_QUALIFIED_CANDIDATE",
        True,
        1
    )

    check(
        "Eligible window reaches collector",
        result["eligibility_passed"] is True
        and result["status"] == "STORED"
        and result["stored"] is True
    )

    kwargs = collector.call_args.kwargs

    check(
        "Correct device and window forwarded",
        kwargs["device_id"] == 2
        and kwargs["completed_end"] == WINDOW_END
    )

    print("\n=== REJECTED WINDOWS ===")

    rejected_statuses = [
        "NO_CAPTURED_PACKETS",
        "INSUFFICIENT_TRAFFIC",
        "ATTRIBUTION_REVIEW",
        "PACKET_COUNT_MISMATCH",
        "MEASUREMENT_REVIEW",
        "OLD_WINDOW_REVIEW",
        "SAFETY_DELAY_NOT_ELAPSED",
        "DEVICE_NOT_FOUND"
    ]

    for status in rejected_statuses:
        result, _ = test_gate(
            status,
            False,
            0
        )

        check(
            status + " blocked",
            result["status"] == status
            and result["stored"] is False
            and result["eligibility_passed"] is False
        )

    print("\n=== COLLECTOR'S SECOND SAFETY CHECK ===")

    result, _ = test_gate(
        "RECENT_QUALIFIED_CANDIDATE",
        True,
        1,
        collector_status="IP_CHANGED"
    )

    check(
        "Collector can independently reject IP change",
        result["status"] == "IP_CHANGED"
        and result["stored"] is False
    )

    print("\n=== RESOURCE SAFETY ===")

    history_count = history_conn.execute("""
        SELECT COUNT(*)
        FROM sqlite_master
        WHERE type = 'table'
          AND name NOT LIKE 'sqlite_%'
    """).fetchone()[0]

    check(
        "No tables or records created by mocks",
        history_count == 0
    )

    print("\n" + "=" * 60)
    print("FINAL RESULTS")
    print("=" * 60)
    print("Passed:", passed)
    print("Failed:", 12 - passed)
    print("Overall:", "PASS" if passed == 12 else "FAIL")
    print("Production database changes: NONE")
    print("Automatic collection: DISABLED")
    print("Baseline learning: DISABLED")
    print("Router operations: NONE")

finally:
    history_conn.close()
    audit_conn.close()
