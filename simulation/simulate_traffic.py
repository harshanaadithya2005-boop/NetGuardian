"""Safe, isolated NetGuardian simulation scenarios."""

from datetime import datetime
from threading import Lock

from simulation.simulation_risk import evaluate_simulation


DEMO_DEVICE_IP = "192.0.2.42"
DEMO_ROGUE_IP = "192.0.2.250"
DEMO_ROGUE_MAC = "DE:AD:BE:EF:00:01"

_demo_history = []
_history_lock = Lock()


def get_target_device(ip_address=None):
    """Return a fictional device without accessing the database."""
    return {
        "id": None,
        "ip_address": DEMO_DEVICE_IP,
        "device_name": "NetGuardian Demo Workstation",
        "device_type": "Test",
        "simulation": True,
    }


def _simulate(name, indicators, description):
    result = evaluate_simulation(indicators)

    event = {
        "scenario": name,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "description": description,
        "risk_score": result["risk_score"],
        "risk_level": result["risk_level"],
        "would_quarantine": result["would_quarantine"],
        "indicators": result["indicators"],
        "simulation": True,
    }

    with _history_lock:
        _demo_history.append(event)

    return (
        f"[DEMO] {description} "
        f"Risk Score: {result['risk_score']}/100 "
        f"({result['risk_level']}). "
        f"Would quarantine: {result['would_quarantine']}."
    )


def simulate_benign_traffic(device_ip=None):
    return _simulate(
        "benign_traffic",
        [],
        f"Normal traffic simulated for {DEMO_DEVICE_IP}.",
    )


def simulate_port_scan(device_ip=None):
    return _simulate(
        "port_scan",
        ["port_scan"],
        f"Port scan simulated from {DEMO_DEVICE_IP} across 15 ports.",
    )


def simulate_dns_anomaly(device_ip=None):
    return _simulate(
        "dns_anomaly",
        ["dns_anomaly"],
        f"DNS anomaly simulated for {DEMO_DEVICE_IP}.",
    )


def simulate_traffic_spike(device_ip=None):
    return _simulate(
        "traffic_spike",
        ["traffic_spike"],
        f"Traffic spike simulated for {DEMO_DEVICE_IP}.",
    )


def simulate_unknown_rogue_device():
    return _simulate(
        "rogue_device",
        ["unknown_device"],
        f"Unknown rogue device simulated: "
        f"IP {DEMO_ROGUE_IP}, MAC {DEMO_ROGUE_MAC}.",
    )


def simulate_critical_incident(device_ip=None):
    return _simulate(
        "critical_attack",
        [
            "port_scan",
            "dns_anomaly",
            "traffic_spike",
            "unknown_device",
        ],
        f"Combined attack simulated against {DEMO_DEVICE_IP}.",
    )


def get_simulation_history():
    with _history_lock:
        return [dict(event) for event in _demo_history]


def reset_simulation():
    """Clear only demonstration history, never real database records."""
    with _history_lock:
        count = len(_demo_history)
        _demo_history.clear()

    return (
        f"[DEMO] Cleared {count} simulation event(s). "
        f"Real database records were not modified."
    )


if __name__ == "__main__":
    print(simulate_benign_traffic())
    print(simulate_port_scan())
    print(simulate_dns_anomaly())
    print(simulate_traffic_spike())
    print(simulate_unknown_rogue_device())
    print(simulate_critical_incident())
    print(reset_simulation())
