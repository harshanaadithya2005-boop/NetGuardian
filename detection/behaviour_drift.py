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
    base_ports = float(len([p for p in base_ports_str.split(",") if p.strip()])) or 3.0
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
    """
    Fetches device baseline and traffic history, then computes live behaviour drift and spikes.
    """
    try:
        from database.models import get_device_profile, get_recent_traffic
        profile = get_device_profile(device_id)
        if not profile:
            return {
                "detected": False,
                "drift_score": 0.0,
                "traffic_spike": False,
                "message": "No baseline profile available yet"
            }

        traffic = recent_traffic if recent_traffic is not None else get_recent_traffic(limit=100, device_id=device_id)

        # Compute observed metrics from traffic
        dns_queries = [t.get("dns_query") for t in traffic if t.get("dns_query")]
        dest_ips = set(t.get("destination_ip") for t in traffic if t.get("destination_ip"))
        dest_ports = set(t.get("destination_port") for t in traffic if t.get("destination_port"))
        total_bytes = sum(t.get("packet_size", 0) for t in traffic)
        total_mb = round(total_bytes / (1024 * 1024), 2)

        observed = {
            "dns_requests": len(dns_queries),
            "distinct_ips": len(dest_ips),
            "distinct_ports": len(dest_ports),
            "data_mb": total_mb
        }

        drift_score, breakdown = calculate_behaviour_drift(observed, profile)
        is_spike = breakdown["bandwidth_mb"]["traffic_spike"]

        has_drift_anomaly = drift_score >= 50.0

        return {
            "detected": has_drift_anomaly or is_spike,
            "drift_score": drift_score,
            "traffic_spike": is_spike,
            "risk_weight": (
                (config.RISK_WEIGHTS.get("behaviour_drift", 15) if has_drift_anomaly else 0) +
                (config.RISK_WEIGHTS.get("traffic_spike", 15) if is_spike else 0)
            ),
            "severity": "HIGH" if drift_score >= 75.0 else ("MEDIUM" if drift_score >= 40.0 else "LOW"),
            "breakdown": breakdown,
            "message": (
                f"Significant Behaviour Drift ({drift_score}%) detected"
                if has_drift_anomaly
                else ("Traffic Volume Spike detected" if is_spike else "Behaviour within normal parameters")
            )
        }
    except Exception as e:
        return {
            "detected": False,
            "drift_score": 0.0,
            "traffic_spike": False,
            "risk_weight": 0,
            "error": str(e)
        }


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