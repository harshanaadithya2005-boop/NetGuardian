
"""
NetGuardian - Safe Behavioral History Collector

Collects completed five-minute observations with
device identity checks.

The caller must supply the destination database
connection. No automatic production writes.
"""

from analytics.behaviour_windows import get_device_window_metrics
from analytics.identity_guard import (
    get_identity_snapshot,
    verify_identity_snapshots,
)
from analytics.baseline_history_v2 import save_observation_v2


def collect_safe_observation(
    conn,
    device_id,
    completed_end,
    minimum_packets=20
):
    """
    Collect and store one behavioral observation.

    Requires an existing V2 history table in conn.

    Returns a status dictionary.
    """

    before = get_identity_snapshot(device_id)

    if before is None:
        return {
            "device_id": device_id,
            "status": "DEVICE_NOT_FOUND",
            "stored": False,
        }

    metrics = get_device_window_metrics(
        device_id=device_id,
        minutes=5,
        end_time=completed_end,
    )

    after = get_identity_snapshot(device_id)

    safe, reason = verify_identity_snapshots(
        before,
        after
    )

    if not safe:
        return {
            "device_id": device_id,
            "status": reason,
            "stored": False,
        }

    if metrics is None:
        return {
            "device_id": device_id,
            "status": "MEASUREMENT_UNAVAILABLE",
            "stored": False,
        }

    if metrics["device_id"] != before["id"]:
        return {
            "device_id": device_id,
            "status": "MEASUREMENT_DEVICE_MISMATCH",
            "stored": False,
        }

    if metrics["ip_address"] != before["ip_address"]:
        return {
            "device_id": device_id,
            "status": "MEASUREMENT_IP_MISMATCH",
            "stored": False,
        }

    inserted = save_observation_v2(
        conn=conn,
        metrics=metrics,
        mac_address=before["mac_address"],
        minimum_packets=minimum_packets
    )

    quality = (
        "QUALIFIED"
        if metrics["packet_count"] >= minimum_packets
        else "INSUFFICIENT"
    )

    return {
        "device_id": device_id,
        "status": (
            "STORED" if inserted else "ALREADY_EXISTS"
        ),
        "stored": inserted,
        "quality": quality,
        "packet_count": metrics["packet_count"],
        "window_start": metrics["window_start"],
        "window_end": metrics["window_end"],
    }
