
"""
NetGuardian - Behavioral Shadow Evaluation

Evaluates five-minute traffic against an explicitly supplied
five-minute baseline without modifying production state.

No database writes, alerts, or quarantine actions.
"""

from analytics.behaviour_windows import get_device_window_metrics
from detection.behaviour_drift import calculate_behaviour_drift


def evaluate_behaviour_shadow(
    device_id,
    baseline_profile,
    minutes=5,
    end_time=None,
    minimum_packets=20
):
    """
    Evaluate a device's observed traffic in read-only mode.

    The caller must provide a baseline measured using
    the same observation interval.
    """

    if minutes != 5:
        raise ValueError(
            "Shadow evaluation currently requires a "
            "five-minute observation window."
        )

    if minimum_packets < 1:
        raise ValueError(
            "minimum_packets must be positive"
        )

    if not baseline_profile:
        raise ValueError(
            "An explicit five-minute baseline is required."
        )

    metrics = get_device_window_metrics(
        device_id=device_id,
        minutes=minutes,
        end_time=end_time
    )

    if metrics is None:
        return {
            "device_id": device_id,
            "status": "DEVICE_NOT_FOUND",
            "detected": False,
        }

    if metrics["packet_count"] < minimum_packets:
        return {
            "device_id": device_id,
            "status": "INSUFFICIENT_OBSERVATION",
            "detected": False,
            "metrics": metrics,
        }

    observed = {
        "dns_requests": metrics["dns_requests"],
        "distinct_ips": metrics["distinct_ips"],
        "distinct_ports": metrics["distinct_ports"],
        "data_mb": metrics["data_mb"],
    }

    drift_score, breakdown = calculate_behaviour_drift(
        observed,
        baseline_profile
    )

    traffic_spike = bool(
        breakdown["bandwidth_mb"]["traffic_spike"]
    )

    behaviour_drift = drift_score >= 50.0

    return {
        "device_id": device_id,
        "status": "EVALUATED",
        "detected": behaviour_drift or traffic_spike,
        "drift_score": drift_score,
        "behaviour_drift": behaviour_drift,
        "traffic_spike": traffic_spike,
        "metrics": metrics,
        "breakdown": breakdown,
        "mode": "SHADOW",
    }
