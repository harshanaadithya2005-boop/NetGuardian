import sys
from pathlib import Path

# Ensure project root is in sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import config


def detect_traffic_spike(normal_mb, current_mb, multiplier=config.TRAFFIC_SPIKE_MULTIPLIER):
    """
    Original function from Member 2:
    Check if observed data volume is >= normal volume multiplied by the spike factor.
    """
    if normal_mb <= 0:
        return current_mb > 50.0
    return current_mb >= normal_mb * multiplier


def calculate_metric_drift(observed, baseline):
    """Calculate percentage change between observed and baseline metric."""
    if baseline <= 0:
        return 1.0 if observed > 0 else 0.0
    diff = observed - baseline
    if diff <= 0:
        return 0.0
    # Ratio over baseline, e.g. (300 - 40) / 40 = 6.5 (650%)
    return diff / baseline


def calculate_behaviour_drift(current_metrics, baseline_profile):
    """
    Computes the multi-dimensional Behaviour Drift Score as defined in
    NetGuardian Proposal Section 8.2.

    Metrics evaluated:
    1. DNS requests volume
    2. Distinct external destination IPs
    3. Distinct ports contacted
    4. Data volume / bandwidth (MB)

    Returns:
        drift_score (float): 0.0 to 100.0 percent
        metric_breakdown (dict): individual drift percentages and raw numbers
    """
    # Baseline defaults
    base_dns = float(baseline_profile.get("normal_dns_rate", 40))
    base_ips = float(baseline_profile.get("normal_dest_ips", 12))
    base_ports_str = str(baseline_profile.get("normal_ports", "80,443,53"))
    base_ports = float(baseline_profile.get("normal_port_count", len([p for p in base_ports_str.split(",") if p.strip()]))) or 3.0
    base_mb = float(baseline_profile.get("normal_bandwidth", 50.0))

    # Observed metrics
    obs_dns = float(current_metrics.get("dns_requests", 0))
    obs_ips = float(current_metrics.get("distinct_ips", 0))
    obs_ports = float(current_metrics.get("distinct_ports", 0))
    obs_mb = float(current_metrics.get("data_mb", 0.0))

    # Calculate raw drift ratios
    drift_dns_ratio = calculate_metric_drift(obs_dns, base_dns)
    drift_ips_ratio = calculate_metric_drift(obs_ips, base_ips)
    drift_ports_ratio = calculate_metric_drift(obs_ports, base_ports)
    drift_mb_ratio = calculate_metric_drift(obs_mb, base_mb)

    # Normalize each ratio into a 0.0 -> 1.0 saturation scale (500% increase saturates component at 1.0)
    norm_dns = min(1.0, drift_dns_ratio / 5.0)
    norm_ips = min(1.0, drift_ips_ratio / 5.0)
    norm_ports = min(1.0, drift_ports_ratio / 5.0)
    norm_mb = min(1.0, drift_mb_ratio / 5.0)

    # Weighted combination (Weights: DNS 25%, IPs 25%, Ports 25%, Bandwidth 25%)
    combined_factor = (norm_dns * 0.25) + (norm_ips * 0.25) + (norm_ports * 0.25) + (norm_mb * 0.25)
    drift_percentage = round(combined_factor * 100.0, 1)

    is_spike = detect_traffic_spike(base_mb, obs_mb)

    breakdown = {
        "dns": {
            "normal": base_dns,
            "observed": obs_dns,
            "drift_pct": round(drift_dns_ratio * 100, 1)
        },
        "distinct_ips": {
            "normal": base_ips,
            "observed": obs_ips,
            "drift_pct": round(drift_ips_ratio * 100, 1)
        },
        "ports": {
            "normal": base_ports,
            "observed": obs_ports,
            "drift_pct": round(drift_ports_ratio * 100, 1)
        },
        "bandwidth_mb": {
            "normal": base_mb,
            "observed": obs_mb,
            "drift_pct": round(drift_mb_ratio * 100, 1),
            "traffic_spike": is_spike
        }
    }

    return drift_percentage, breakdown


def check_behaviour_drift_for_device(device_id, recent_traffic=None):
    """Compare all outbound real traffic in five minutes with matching baselines.

    recent_traffic is retained for callers using the earlier API. Aggregation
    deliberately uses SQL so a busy device cannot hide behind a 100-row limit.
    """
    from datetime import datetime, timedelta
    from database.models import get_device_profile, get_device_by_id
    from analytics.behaviour_windows import get_device_window_metrics
    from analytics.learned_baseline import get_learned_baseline
    device = get_device_by_id(device_id)
    if not device:
        return {"detected": False, "drift_score": 0.0, "traffic_spike": False,
                "status": "DEVICE_NOT_FOUND", "message": "Device not found"}
    end = datetime.now()
    metrics = get_device_window_metrics(device_id, minutes=5, end_time=end)
    profile, windows = get_learned_baseline(device_id, device.get("mac_address"), end-timedelta(minutes=5))
    source = "LEARNED"
    if profile is not None:
        from analytics.collection_schedule import get_safe_completed_window_end
        end=get_safe_completed_window_end(now=end)
        metrics=get_device_window_metrics(device_id,minutes=5,end_time=end)
        quality=observation_quality(device_id,end)
        if not quality['eligible']:
            return dict(detected=False,drift_score=0.0,traffic_spike=False,status='INCOMPLETE_OBSERVATION',
                        baseline_source=source,baseline_windows=windows,metrics=metrics,quality=quality,
                        message='Completed behavioral window rejected: '+quality['status'])
    if profile is None:
        profile = get_device_profile(device_id)
        source = "CONFIGURED"
        if not profile:
            return {"detected": False, "drift_score": 0.0, "traffic_spike": False,
                    "status": "NO_BASELINE", "message": "No baseline profile available yet"}
        # Configured volume/rate budgets are per day. Use the same five-minute
        # interval as the observation, with floors for sparse IoT activity.
        profile = dict(profile)
        profile["normal_bandwidth"] = max(0.05, float(profile["normal_bandwidth"])/288)
        profile["normal_dns_rate"] = max(5, float(profile["normal_dns_rate"])/288)
    if metrics["packet_count"] < 20:
        return {"detected": False, "drift_score": 0.0, "traffic_spike": False,
                "status": "INSUFFICIENT_OBSERVATION", "baseline_source": source,
                "baseline_windows": windows, "metrics": metrics,
                "message": "At least 20 outbound packets in five minutes are required"}
    score, breakdown = calculate_behaviour_drift(metrics, profile)
    spike = breakdown["bandwidth_mb"]["traffic_spike"]
    # Daily factory budgets are not learned evidence. Keep their comparison
    # visible during warmup, but do not turn it into a behavioral alert that
    # would prevent clean observations from ever qualifying for learning.
    provisional = source != "LEARNED"
    detected = not provisional and (score >= 50 or spike)
    return {"detected": detected, "drift_score": score, "traffic_spike": spike,
            "status": "BASELINE_WARMUP" if provisional else "EVALUATED",
            "provisional": provisional, "baseline_source": source, "baseline_windows": windows,
            "window_minutes": 5, "metrics": metrics, "breakdown": breakdown,
            "message": (f"Baseline warming up: {windows}/12 qualified windows; comparison is provisional"
                        if provisional else "Behavior anomaly detected" if detected else "Behavior within baseline limits")}


def observation_quality(device_id,end):
    from database.db import get_connection
    from analytics.window_eligibility import assess_window_eligibility
    from analytics.capture_heartbeat import assess_heartbeat_window
    from analytics.capture_sessions_v2 import assess_session_transitions_v2
    conn=get_connection()
    try:
        quality=assess_window_eligibility(conn,device_id,end)
        if not assess_heartbeat_window(conn,end)['heartbeat_candidate'] or not assess_session_transitions_v2(conn,end)['transition_free']:
            return dict(eligible=False,status='CAPTURE_COVERAGE_OR_SESSION_REVIEW')
        return quality
    finally:conn.close()


if __name__ == "__main__":
    # Test with the proposal's Laptop-04 worked example
    print("Testing Behaviour Drift Score (Proposal Section 8.2 - Laptop-04):")
    sample_baseline = {
        "normal_dns_rate": 40,
        "normal_dest_ips": 12,
        "normal_ports": "80,443,53,22,21",
        "normal_bandwidth": 50.0
    }
    sample_observed = {
        "dns_requests": 300,
        "distinct_ips": 85,
        "distinct_ports": 42,
        "data_mb": 900.0
    }
    drift, breakdown = calculate_behaviour_drift(sample_observed, sample_baseline)
    print(f"Calculated Drift Score: {drift}%")
    print("Breakdown:")
    for k, v in breakdown.items():
        print(f"  - {k}: {v}")
