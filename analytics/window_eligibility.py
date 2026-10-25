
"""
NetGuardian - Historical Window Eligibility

Read-only eligibility assessment for completed
five-minute behavioral observation windows.

Does not insert history or update learned baselines.
"""

from datetime import datetime, timedelta

from analytics.behaviour_windows import (
    get_device_window_metrics
)
from analytics.identity_guard import (
    get_identity_snapshot,
    verify_identity_snapshots
)
from analytics.traffic_attribution import (
    audit_device_traffic
)

from analytics.capture_continuity import (
    assess_capture_continuity
)


def assess_window_eligibility(
    conn,
    device_id,
    window_end,
    now=None,
    max_age_minutes=15,
    minimum_packets=20
):
    """
    Review one completed five-minute window.

    conn must be a read-only production connection
    when used for auditing real traffic.
    """

    current = now if now is not None else datetime.now()

    if not isinstance(window_end, datetime):
        raise TypeError("window_end must be a datetime")

    if not isinstance(current, datetime):
        raise TypeError("now must be a datetime")

    if current.tzinfo is not None or window_end.tzinfo is not None:
        raise ValueError("Use local naive timestamps")

    if (
        window_end.minute % 5 != 0
        or window_end.second != 0
        or window_end.microsecond != 0
    ):
        raise ValueError("Window end must align to five minutes")

    if max_age_minutes < 2:
        raise ValueError("Maximum age must be at least 2 minutes")

    if minimum_packets < 1:
        raise ValueError("Minimum packets must be positive")

    age = current - window_end

    if age < timedelta(minutes=2):
        return {
            "status": "SAFETY_DELAY_NOT_ELAPSED",
            "eligible": False
        }

    if age > timedelta(minutes=max_age_minutes):
        return {
            "status": "OLD_WINDOW_REVIEW",
            "eligible": False
        }

    before = get_identity_snapshot(device_id)

    if before is None:
        return {
            "status": "DEVICE_NOT_FOUND",
            "eligible": False
        }

    metrics = get_device_window_metrics(
        device_id=device_id,
        minutes=5,
        end_time=window_end
    )

    after = get_identity_snapshot(device_id)

    identity_safe, reason = verify_identity_snapshots(
        before, after
    )

    if not identity_safe:
        return {
            "status": reason,
            "eligible": False
        }

    expected_end = window_end.isoformat(timespec="seconds")
    expected_start = (
        window_end - timedelta(minutes=5)
    ).isoformat(timespec="seconds")

    if (
        metrics is None
        or metrics.get("device_id") != device_id
        or metrics.get("ip_address") != before["ip_address"]
        or metrics.get("window_start") != expected_start
        or metrics.get("window_end") != expected_end
    ):
        return {
            "status": "MEASUREMENT_REVIEW",
            "eligible": False
        }

    audit = audit_device_traffic(
        conn=conn,
        device_id=device_id,
        device_ip=before["ip_address"],
        window_end=window_end
    )

    if audit["status"] == "NO_CAPTURED_PACKETS":
        status = "NO_CAPTURED_PACKETS"
        eligible = False

    elif audit["status"] != "ENDPOINTS_CONSISTENT":
        status = "ATTRIBUTION_REVIEW"
        eligible = False

    elif audit["outbound"] != metrics["packet_count"]:
        status = "PACKET_COUNT_MISMATCH"
        eligible = False

    elif metrics["packet_count"] < minimum_packets:
        status = "INSUFFICIENT_TRAFFIC"
        eligible = False

    else:
        # Check global capture evidence only after the
        # packet attribution and volume checks pass.
        continuity = assess_capture_continuity(
            conn=conn,
            window_end=window_end
        )

        if not continuity["continuity_candidate"]:
            status = "CAPTURE_CONTINUITY_REVIEW"
            eligible = False
        else:
            status = "RECENT_QUALIFIED_CANDIDATE"
            eligible = True

    return {
        "device_id": device_id,
        "window_end": expected_end,
        "status": status,
        "eligible": eligible,
        "packet_count": metrics["packet_count"],
        "inbound_packets": audit["inbound"],
        "unattributed_packets": audit["unattributed"],
        "mac_address": before["mac_address"],
        "ip_address": before["ip_address"]
    }
